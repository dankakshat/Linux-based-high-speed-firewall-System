"""Attack simulation lab for testing XDP-Engine detection and mitigation."""

from __future__ import annotations

import argparse
from pathlib import Path
import time

from xdp_engine.backends import SimulatorBackend
from xdp_engine.engine import XDPEngine
from xdp_engine.models import OperatingMode


def write_http_exploits(http_log: Path, attacker_ip: str = "203.0.113.45") -> None:
    """Append simulated SQL injection and directory traversal log entries."""
    http_log.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f'{attacker_ip} - - [25/Nov/2026:19:00:01 +0000] "GET /?id=1%27%20OR%201=1-- HTTP/1.1" 200 512\n',
        f'{attacker_ip} - - [25/Nov/2026:19:00:02 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 162\n',
    ]
    with http_log.open("a", encoding="utf-8") as fh:
        fh.writelines(lines)


def write_ssh_bruteforce(
    ssh_log: Path, attacker_ip: str = "198.51.100.77", attempts: int = 5
) -> None:
    """Append simulated failed SSH login lines."""
    ssh_log.parent.mkdir(parents=True, exist_ok=True)
    with ssh_log.open("a", encoding="utf-8") as fh:
        for idx in range(attempts):
            fh.write(
                f"Nov 25 19:01:0{idx} server sshd[900{idx}]: Failed password for invalid user admin from {attacker_ip} port {41000 + idx} ssh2\n"
            )


def run_full_demo(base_dir: Path) -> None:
    """Run an end-to-end simulation covering all 5 attack scenarios."""
    backend = SimulatorBackend()
    engine = XDPEngine(
        interface="sim0",
        backend=backend,
        base_dir=base_dir,
        mode=OperatingMode.ENFORCE,
        enable_ipc=False,
    )
    engine.start()
    try:
        print("[1/5] Simulating Web SQLi & Path Traversal...")
        write_http_exploits(base_dir / "logs" / "http_access.log", "203.0.113.45")
        engine.step_once()

        print("[2/5] Simulating SSH Brute Force (5 attempts)...")
        write_ssh_bruteforce(base_dir / "logs" / "ssh_auth.log", "198.51.100.77", attempts=5)
        engine.step_once()

        print("[3/5] Simulating Port Scan (15 ports)...")
        for port in range(20, 35):
            backend.process_packet("192.0.2.88", protocol="TCP", dst_port=port, syn_only=True)
        engine.step_once()

        print("[4/5] Simulating Multi-Stage Correlation (SCAN_THEN_BRUTE)...")
        for port in range(80, 95):
            backend.process_packet("192.0.2.99", protocol="TCP", dst_port=port, syn_only=True)
        engine.step_once()
        write_ssh_bruteforce(base_dir / "logs" / "ssh_auth.log", "192.0.2.99", attempts=1)
        engine.step_once()

        print("[5/5] Simulating Volumetric SYN Flood (dropped in enforce mode)...")
        for _ in range(150):
            backend.process_packet("203.0.113.200", protocol="TCP", dst_port=80, syn_only=True)
        engine.step_once()
        # Send follow-up flood packets after block takes effect.
        backend.process_packet("203.0.113.200", protocol="TCP", dst_port=80, syn_only=True, count=5000)
        engine.step_once()

        print("\n--- Engine Stats ---")
        print(engine.handle_command("stats"))
        print("\n--- Active Blocks ---")
        print(engine.handle_command("list"))
        print("\n--- Recent Alerts ---")
        print(engine.handle_command("alerts"))
        time.sleep(0.2)
    finally:
        engine.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="XDP-Engine Attack Simulation Lab")
    parser.add_argument(
        "--scenario",
        choices=["all-demo", "http", "ssh"],
        default="all-demo",
        help="Run full in-process demo or append log lines for a running daemon",
    )
    parser.add_argument("--base-dir", default=".")
    args = parser.parse_args()

    base = Path(args.base_dir)
    if args.scenario == "http":
        write_http_exploits(base / "logs" / "http_access.log")
        print("Appended HTTP SQLi/traversal test lines to logs/http_access.log")
    elif args.scenario == "ssh":
        write_ssh_bruteforce(base / "logs" / "ssh_auth.log")
        print("Appended SSH brute-force test lines to logs/ssh_auth.log")
    else:
        run_full_demo(base)


if __name__ == "__main__":
    main()
