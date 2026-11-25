"""Unit and integration tests for XDP-Engine."""

from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import time
import unittest

from dashboard.app import create_app
from xdp_engine.backends.simulator import SimulatorBackend
from xdp_engine.detectors import HttpDetector, LogTailer, SshDetector
from xdp_engine.engine import XDPEngine
from xdp_engine.ipc import send_ipc_command
from xdp_engine.models import OperatingMode, SecurityEvent
from xdp_engine.rule_engine import RuleEngine


REPO_ROOT = Path(__file__).resolve().parent.parent


class DetectorTests(unittest.TestCase):
    def test_http_detector_sqli_and_traversal(self) -> None:
        detector = HttpDetector()
        sqli = detector.parse_line(
            '203.0.113.10 - - [25/Nov/2026:12:00:00 +0000] "GET /?id=1%27%20OR%201=1-- HTTP/1.1" 200 100'
        )
        self.assertIsNotNone(sqli)
        self.assertEqual(sqli.event_type, "http_sqli")
        self.assertEqual(sqli.src_ip, "203.0.113.10")

        trav = detector.parse_line(
            '203.0.113.11 - - [25/Nov/2026:12:00:00 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 10'
        )
        self.assertIsNotNone(trav)
        self.assertEqual(trav.src_ip, "203.0.113.11")

        clean = detector.parse_line(
            '203.0.113.12 - - [25/Nov/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024'
        )
        self.assertIsNone(clean)

    def test_ssh_detector(self) -> None:
        detector = SshDetector()
        evt = detector.parse_line(
            "Nov 25 12:00:01 host sshd[123]: Failed password for invalid user root from 198.51.100.22 port 55211 ssh2"
        )
        self.assertIsNotNone(evt)
        self.assertEqual(evt.event_type, "ssh_failed")
        self.assertEqual(evt.src_ip, "198.51.100.22")

    def test_log_tailer_reads_appended_and_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "test.log"
            log_file.write_text("initial\n", encoding="utf-8")
            seen: list[str] = []
            tailer = LogTailer(log_file, seen.append, from_end=True)

            self.assertEqual(tailer.poll(), 0)
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write("line1\nline2\n")
            self.assertEqual(tailer.poll(), 2)
            self.assertEqual(seen, ["line1", "line2"])

            # Simulate log truncation/rotation.
            log_file.write_text("rotated\n", encoding="utf-8")
            self.assertEqual(tailer.poll(), 1)
            self.assertEqual(seen[-1], "rotated")


class RuleEngineTests(unittest.TestCase):
    def test_threshold_and_sequence_correlation(self) -> None:
        engine = RuleEngine(REPO_ROOT / "rules.yaml")
        now = time.time()

        # 4 SSH failures should not trigger SSH_BRUTE_FORCE (threshold 5).
        for idx in range(4):
            alerts = engine.evaluate(
                SecurityEvent(event_type="ssh_failed", src_ip="198.51.100.5", timestamp=now + idx)
            )
            self.assertEqual(alerts, [])

        # 5th failure triggers SSH_BRUTE_FORCE.
        alerts = engine.evaluate(
            SecurityEvent(event_type="ssh_failed", src_ip="198.51.100.5", timestamp=now + 4)
        )
        self.assertEqual([a.rule_name for a in alerts], ["SSH_BRUTE_FORCE"])

        # Sequence: port_scan followed by ssh_failed triggers SCAN_THEN_BRUTE.
        scan_alerts = engine.evaluate(
            SecurityEvent(event_type="port_scan", src_ip="192.0.2.50", timestamp=now)
        )
        self.assertEqual([a.rule_name for a in scan_alerts], ["PORT_SCAN"])

        seq_alerts = engine.evaluate(
            SecurityEvent(event_type="ssh_failed", src_ip="192.0.2.50", timestamp=now + 10)
        )
        self.assertEqual([a.rule_name for a in seq_alerts], ["SCAN_THEN_BRUTE"])


class EndToEndEngineAndDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="xdp_test_"))
        for fname in ("rules.yaml", "playbooks.yaml", "known_ips.txt", "blocklist.txt"):
            shutil.copy(REPO_ROOT / fname, self.tmp_dir / fname)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_engine_detect_vs_enforce_ipc_and_dashboard(self) -> None:
        backend = SimulatorBackend(scan_port_threshold=5, syn_flood_threshold=20)
        engine = XDPEngine(
            interface="sim0",
            backend=backend,
            base_dir=self.tmp_dir,
            mode=OperatingMode.DETECT,
            ipc_port=0,  # OS picks a free ephemeral port
            enable_ipc=True,
        )
        engine.start()
        try:
            ipc_port = engine._ipc.port  # type: ignore[union-attr]

            # Guardrail: localhost cannot be blocked.
            guard_resp = engine.handle_command("block 127.0.0.1 60")
            self.assertIn("Refused", guard_resp)

            # In DETECT mode, SQLi generates alert but does not block packets.
            with (self.tmp_dir / "logs" / "http_access.log").open("a", encoding="utf-8") as fh:
                fh.write(
                    '203.0.113.55 - - [25/Nov/2026:12:00:00 +0000] "GET /?q=UNION+SELECT+1 HTTP/1.1" 200 50\n'
                )
            engine.step_once()
            self.assertEqual(len(backend.list_blocked()), 0)
            self.assertTrue(backend.process_packet("203.0.113.55", protocol="TCP", dst_port=80))

            # Switch to ENFORCE via IPC CLI channel.
            ipc_out = send_ipc_command("mode enforce", port=ipc_port)
            self.assertIn("ENFORCE", ipc_out)

            # Trigger HTTP_ATTACK again -> now blocked & dropped.
            with (self.tmp_dir / "logs" / "http_access.log").open("a", encoding="utf-8") as fh:
                fh.write(
                    '203.0.113.55 - - [25/Nov/2026:12:00:05 +0000] "GET /../../etc/passwd HTTP/1.1" 404 50\n'
                )
            engine.step_once()
            self.assertEqual(len(backend.list_blocked()), 1)
            self.assertFalse(backend.process_packet("203.0.113.55", protocol="TCP", dst_port=80))
            engine.step_once()
            self.assertGreaterEqual(backend.get_stats().dropped, 1)

            # Verify Flask dashboard renders and serves live SQLite telemetry.
            app = create_app(self.tmp_dir / "engine.db")
            client = app.test_client()

            self.assertEqual(client.get("/").status_code, 200)
            self.assertEqual(client.get("/?showcase=1").status_code, 200)

            overview = client.get("/api/overview").get_json()
            self.assertEqual(overview["status"]["mode"], "enforce")
            self.assertEqual(overview["status"]["status"], "ONLINE")
            self.assertGreaterEqual(len(overview["alerts"]), 2)
            self.assertEqual(overview["blocks"][0]["ip"], "203.0.113.55")
        finally:
            engine.stop()


if __name__ == "__main__":
    unittest.main()
