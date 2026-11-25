"""Log tailers and application-layer intrusion detectors."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Callable
from urllib.parse import unquote, unquote_plus

from .models import SecurityEvent
from .utils import is_valid_ip


# Common Nginx / Apache combined log format: 1.2.3.4 - - [date] "GET /path HTTP/1.1" 200 ...
_HTTP_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)[^"]*"\s+(?P<status>\d{3})'
)

# Common SSH auth failure patterns from /var/log/auth.log or /var/log/secure
_SSH_FAIL_RE = re.compile(
    r"(?:Failed password|Invalid user|Disconnected from authenticating user).*?\bfrom\s+(?P<ip>[0-9a-fA-F:.]+)"
)

_DEFAULT_HTTP_PATTERNS = (
    re.compile(r"union\s+(?:all\s+)?select", re.IGNORECASE),
    re.compile(r"'\s*or\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"%2e%2e", re.IGNORECASE),
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
)


class HttpDetector:
    """Detects SQL injection, path traversal, and XSS probes in HTTP access logs."""

    def __init__(self, extra_patterns: list[str] | None = None) -> None:
        self._patterns = list(_DEFAULT_HTTP_PATTERNS)
        if extra_patterns:
            for pat in extra_patterns:
                self._patterns.append(re.compile(pat, re.IGNORECASE))

    def parse_line(self, line: str) -> SecurityEvent | None:
        """Inspect a single HTTP access log line and return an event if malicious."""
        match = _HTTP_LOG_RE.match(line.strip())
        if not match:
            return None

        src_ip = match.group("ip")
        if not is_valid_ip(src_ip):
            return None

        raw_uri = match.group("uri")
        decoded_uri = unquote_plus(unquote(raw_uri))
        combined = f"{raw_uri} {decoded_uri}"

        for pattern in self._patterns:
            if pattern.search(combined):
                return SecurityEvent(
                    event_type="http_sqli",
                    src_ip=src_ip,
                    target=raw_uri[:200],
                    payload=raw_uri[:300],
                    metadata={
                        "method": match.group("method"),
                        "status": match.group("status"),
                        "matched_pattern": pattern.pattern,
                    },
                )
        return None


class SshDetector:
    """Detects failed SSH authentication attempts in auth/secure logs."""

    def parse_line(self, line: str) -> SecurityEvent | None:
        """Inspect a single auth log line and return an event on SSH failure."""
        match = _SSH_FAIL_RE.search(line)
        if not match:
            return None

        src_ip = match.group("ip")
        if not is_valid_ip(src_ip):
            return None

        return SecurityEvent(
            event_type="ssh_failed",
            src_ip=src_ip,
            target="ssh:22",
            payload=line.strip()[:300],
        )


class LogTailer:
    """Non-blocking file tailer that survives log rotation and truncation."""

    def __init__(
        self,
        path: str | Path,
        on_line: Callable[[str], None],
        from_end: bool = True,
    ) -> None:
        self.path = Path(path)
        self._on_line = on_line
        self._from_end = from_end
        if from_end and self.path.exists():
            self._offset = self.path.stat().st_size
            self._initialized = True
        else:
            self._offset = 0
            self._initialized = not from_end

    def poll(self) -> int:
        """Read any newly appended complete lines. Returns number of lines read."""
        if not self.path.exists():
            return 0

        try:
            size = self.path.stat().st_size
            if not self._initialized:
                self._offset = size if self._from_end else 0
                self._initialized = True
            elif size < self._offset:
                # Log file rotated or truncated.
                self._offset = 0

            if size == self._offset:
                return 0

            lines_read = 0
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
                self._offset = fh.tell()

            for line in chunk.splitlines():
                stripped = line.strip()
                if stripped:
                    self._on_line(stripped)
                    lines_read += 1
            return lines_read
        except OSError:
            return 0
