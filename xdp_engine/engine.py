"""Main XDP-Engine daemon orchestrating detection, SOAR playbooks, and telemetry."""

from __future__ import annotations

import argparse
from pathlib import Path
import signal
import sys
import threading
import time

from .backends import BccXdpBackend, PacketBackend, SimulatorBackend, is_bcc_available
from .detectors import HttpDetector, LogTailer, SshDetector
from .ipc import DEFAULT_IPC_PORT, IPCServer
from .models import OperatingMode, SecurityEvent
from .notifier import Notifier
from .playbook_runner import PlaybookRunner
from .rule_engine import RuleEngine
from .storage import Storage
from .utils import discover_local_guardrail_ips, is_valid_ip, load_ip_list_file


class XDPEngine:
    """Core runtime combining packet filtering, log detection, and SOAR response."""

    def __init__(
        self,
        interface: str = "eth0",
        backend: PacketBackend | None = None,
        base_dir: str | Path = ".",
        db_path: str | Path | None = None,
        mode: OperatingMode = OperatingMode.DETECT,
        http_logs: list[Path] | None = None,
        ssh_logs: list[Path] | None = None,
        ipc_port: int = DEFAULT_IPC_PORT,
        enable_ipc: bool = True,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.interface = interface
        self.backend = backend or self._select_backend("auto")
        self.storage = Storage(db_path or (self.base_dir / "engine.db"))
        self.notifier = Notifier()
        self.rule_engine = RuleEngine(self.base_dir / "rules.yaml")

        guardrails = discover_local_guardrail_ips()
        guardrails.update(load_ip_list_file(self.base_dir / "known_ips.txt"))

        self.playbook_runner = PlaybookRunner(
            playbooks_path=self.base_dir / "playbooks.yaml",
            backend=self.backend,
            storage=self.storage,
            notifier=self.notifier,
            guardrail_ips=guardrails,
        )
        self.http_detector = HttpDetector()
        self.ssh_detector = SshDetector()

        self._tailers: list[LogTailer] = []
        self._configure_tailers(http_logs, ssh_logs)

        self._stop_event = threading.Event()
        self._step_lock = threading.Lock()
        self._worker_thread: threading.Thread | None = None
        self._ipc: IPCServer | None = None
        self._ipc_port = ipc_port
        self._enable_ipc = enable_ipc
        self._initial_mode = mode

    @staticmethod
    def _select_backend(choice: str) -> PacketBackend:
        if choice == "bcc":
            return BccXdpBackend()
        if choice == "sim":
            return SimulatorBackend()
        if is_bcc_available():
            return BccXdpBackend()
        return SimulatorBackend()

    def _configure_tailers(
        self,
        http_logs: list[Path] | None,
        ssh_logs: list[Path] | None,
    ) -> None:
        local_logs = self.base_dir / "logs"
        local_logs.mkdir(parents=True, exist_ok=True)
        local_http = local_logs / "http_access.log"
        local_ssh = local_logs / "ssh_auth.log"
        local_http.touch(exist_ok=True)
        local_ssh.touch(exist_ok=True)

        http_paths = list(http_logs or [local_http])
        ssh_paths = list(ssh_logs or [local_ssh])

        if sys.platform.startswith("linux") and http_logs is None:
            sys_nginx = Path("/var/log/nginx/access.log")
            if sys_nginx.exists():
                http_paths.append(sys_nginx)
        if sys.platform.startswith("linux") and ssh_logs is None:
            for candidate in (Path("/var/log/auth.log"), Path("/var/log/secure")):
                if candidate.exists():
                    ssh_paths.append(candidate)

        for path in http_paths:
            self._tailers.append(
                LogTailer(path, lambda line: self._on_log_line(self.http_detector.parse_line(line)))
            )
        for path in ssh_paths:
            self._tailers.append(
                LogTailer(path, lambda line: self._on_log_line(self.ssh_detector.parse_line(line)))
            )

    def _on_log_line(self, event: SecurityEvent | None) -> None:
        if event is not None:
            self.ingest_event(event)

    def ingest_event(self, event: SecurityEvent) -> int:
        """Process a normalized SecurityEvent through rules and playbooks.

        Returns the number of triggered alerts.
        """
        alerts = self.rule_engine.evaluate(event)
        for alert in alerts:
            self.playbook_runner.execute(alert)
        if alerts:
            self.storage.sync_blocked_ips(self.backend.list_blocked())
        return len(alerts)

    def start(self) -> None:
        """Attach backend, load static lists, and start telemetry worker."""
        self.backend.attach(self.interface)
        for ip in self.playbook_runner.guardrail_ips:
            self.backend.allow_ip(ip)
        for ip in load_ip_list_file(self.base_dir / "blocklist.txt"):
            if ip not in self.playbook_runner.guardrail_ips:
                self.backend.block_ip(ip, ttl_seconds=0, reason="static_blocklist")

        self.playbook_runner.set_mode(self._initial_mode)
        self._sync_storage()
        self.storage.add_feed_event(
            "info",
            "SYSTEM",
            f"Engine started on {self.interface} ({self.backend.name}) in {self._initial_mode.value.upper()} mode",
        )

        if self._enable_ipc:
            self._ipc = IPCServer(self.handle_command, port=self._ipc_port)
            self._ipc.start()

        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        """Cleanly detach XDP, stop background threads, and mark offline."""
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        if self._ipc is not None:
            self._ipc.stop()
            self._ipc = None
        self.backend.detach()
        self.storage.add_feed_event("info", "SYSTEM", "Engine stopped cleanly")
        self.storage.mark_offline()

    def step_once(self) -> None:
        """Run one synchronous poll/housekeeping cycle (useful for tests too)."""
        with self._step_lock:
            for tailer in self._tailers:
                tailer.poll()
            for net_event in self.backend.poll_events():
                self.ingest_event(net_event)
            expired = self.backend.purge_expired()
            for ip in expired:
                self.storage.add_feed_event("info", "EXPIRE", f"Ban expired for {ip}")
            self._sync_storage()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self.step_once()
            self._stop_event.wait(0.5)

    def _sync_storage(self) -> None:
        stats = self.backend.get_stats()
        self.storage.update_status(
            status="ONLINE",
            mode=self.playbook_runner.mode,
            interface=self.interface,
            backend=self.backend.name,
            stats=stats,
        )
        self.storage.sync_blocked_ips(self.backend.list_blocked())

    def handle_command(self, command_line: str) -> str:
        """Execute an interactive or IPC control command and return response text."""
        parts = command_line.strip().split()
        if not parts:
            return ""
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("enforce", "detect"):
            args = [cmd]
            cmd = "mode"

        if cmd == "mode":
            if not args or args[0].lower() == "show":
                return f"Current mode: {self.playbook_runner.mode.value.upper()}"
            target = args[0].lower()
            if target not in ("detect", "enforce"):
                return "Usage: mode <detect|enforce|show>"
            new_mode = OperatingMode(target)
            self.playbook_runner.set_mode(new_mode)
            self._sync_storage()
            self.storage.add_feed_event("warn", "MODE", f"Switched to {new_mode.value.upper()} mode")
            return f"Mode switched to {new_mode.value.upper()}"

        if cmd == "block":
            if not args or not is_valid_ip(args[0]):
                return "Usage: block <IP> [TTL_SECONDS]"
            ip = args[0]
            if ip in self.playbook_runner.guardrail_ips:
                return f"Refused: {ip} is protected by whitelist/guardrail."
            try:
                ttl = int(args[1]) if len(args) > 1 else 600
            except ValueError:
                return "TTL_SECONDS must be an integer."
            self.backend.block_ip(ip, ttl_seconds=ttl, reason="manual")
            self._sync_storage()
            self.storage.add_feed_event("warn", "MANUAL", f"Blocked {ip} (ttl={ttl}s)")
            return f"Blocked {ip} for {ttl}s"

        if cmd == "unblock":
            if not args or not is_valid_ip(args[0]):
                return "Usage: unblock <IP>"
            ip = args[0]
            removed = self.backend.unblock_ip(ip)
            self._sync_storage()
            if removed:
                self.storage.add_feed_event("info", "MANUAL", f"Unblocked {ip}")
                return f"Unblocked {ip}"
            return f"{ip} was not in the block table."

        if cmd == "allow":
            if not args or not is_valid_ip(args[0]):
                return "Usage: allow <IP>"
            ip = args[0]
            self.playbook_runner.add_whitelist_ip(ip)
            self._sync_storage()
            self.storage.add_feed_event("info", "WHITELIST", f"Whitelisted {ip}")
            return f"Whitelisted {ip}"

        if cmd == "unallow":
            if not args or not is_valid_ip(args[0]):
                return "Usage: unallow <IP>"
            ip = args[0]
            removed = self.playbook_runner.remove_whitelist_ip(ip)
            return f"Removed {ip} from whitelist." if removed else f"{ip} was not whitelisted."

        if cmd == "list":
            entries = self.backend.list_blocked()
            if not entries:
                return "No active blocked IPs."
            lines = ["IP               | Hits     | Remaining | Reason"]
            lines.append("-" * 60)
            for e in entries:
                rem = "permanent" if e.remaining_seconds < 0 else f"{e.remaining_seconds}s"
                lines.append(f"{e.ip:<16} | {e.hits:<8} | {rem:<9} | {e.reason}")
            return "\n".join(lines)

        if cmd == "stats":
            s = self.backend.get_stats()
            return (
                f"Mode={self.playbook_runner.mode.value.upper()} | Backend={self.backend.name} | "
                f"Dropped={s.dropped} ({s.drop_rate_pps}/s) | Passed={s.passed} | "
                f"TCP={s.tcp} UDP={s.udp} ICMP={s.icmp}"
            )

        if cmd == "alerts":
            rows = self.storage.get_alerts(limit=10)
            if not rows:
                return "No alerts recorded yet."
            lines = []
            for r in rows:
                status = "ENFORCED" if r["enforced"] else "DETECTED"
                lines.append(
                    f"[{r['severity'].upper()}] {r['rule_name']} | {r['src_ip']} | {status} | {r['details']}"
                )
            return "\n".join(lines)

        if cmd == "status":
            st = self.storage.get_status()
            return (
                f"Status={st['status']} | Mode={st['mode'].upper()} | "
                f"Interface={st['interface']} | Backend={st['backend']} | Dropped={st['dropped']}"
            )

        if cmd == "help":
            return (
                "Commands: mode <enforce|detect|show>, block <IP> [TTL], unblock <IP>, "
                "allow <IP>, unallow <IP>, list, stats, alerts, status, quit"
            )

        if cmd in ("quit", "exit"):
            self._stop_event.set()
            return "Shutting down engine..."

        return f"Unknown command '{cmd}'. Type 'help' for available commands."


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the engine daemon."""
    parser = argparse.ArgumentParser(description="XDP-Engine Python Security Daemon")
    parser.add_argument("interface", nargs="?", default="sim0", help="Network interface (e.g. eth0, sim0)")
    parser.add_argument("--backend", choices=["auto", "bcc", "sim"], default="auto")
    parser.add_argument("--mode", choices=["detect", "enforce"], default="detect")
    parser.add_argument("--base-dir", default=".", help="Project root containing rules/playbooks")
    parser.add_argument("--ipc-port", type=int, default=DEFAULT_IPC_PORT)
    parser.add_argument("--no-interactive", action="store_true", help="Run without stdin prompt")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Entry point for running XDP-Engine."""
    args = parse_args(argv)
    backend = XDPEngine._select_backend(args.backend)
    engine = XDPEngine(
        interface=args.interface,
        backend=backend,
        base_dir=args.base_dir,
        mode=OperatingMode(args.mode),
        ipc_port=args.ipc_port,
    )

    def _handle_sig(_signum: int, _frame: object) -> None:
        engine._stop_event.set()

    signal.signal(signal.SIGINT, _handle_sig)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_sig)

    engine.start()
    print(
        f"[XDP-Engine] Running on '{args.interface}' | Backend: {backend.name} | "
        f"Mode: {args.mode.upper()} | IPC port: {args.ipc_port}"
    )
    print("Type 'help' for commands, 'enforce' / 'detect' to switch modes, or 'quit' to exit.")

    try:
        if args.no_interactive:
            while not engine._stop_event.is_set():
                time.sleep(0.5)
        else:
            while not engine._stop_event.is_set():
                try:
                    line = input("xdp> ")
                except EOFError:
                    time.sleep(0.5)
                    continue
                if not line.strip():
                    continue
                out = engine.handle_command(line)
                if out:
                    print(out)
                if line.strip().lower() in ("quit", "exit"):
                    break
    finally:
        engine.stop()


if __name__ == "__main__":
    main()
