"""Cross-platform localhost JSON IPC server and client for engine control."""

from __future__ import annotations

import json
import socket
import socketserver
import threading
from typing import Callable


DEFAULT_IPC_HOST = "127.0.0.1"
DEFAULT_IPC_PORT = 5051


class _IPCRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(8192).decode("utf-8", errors="replace").strip()
        if not raw:
            return
        try:
            req = json.loads(raw)
            cmd = str(req.get("command", "")).strip()
        except json.JSONDecodeError:
            cmd = raw

        handler: Callable[[str], str] = self.server.command_handler  # type: ignore[attr-defined]
        output = handler(cmd)
        resp = json.dumps({"ok": True, "output": output}) + "\n"
        self.wfile.write(resp.encode("utf-8"))


class _ReusableTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class IPCServer:
    """Background localhost control socket server."""

    def __init__(
        self,
        command_handler: Callable[[str], str],
        host: str = DEFAULT_IPC_HOST,
        port: int = DEFAULT_IPC_PORT,
    ) -> None:
        self._server = _ReusableTCPServer((host, port), _IPCRequestHandler)
        self._server.command_handler = command_handler  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def send_ipc_command(
    command: str,
    host: str = DEFAULT_IPC_HOST,
    port: int = DEFAULT_IPC_PORT,
    timeout: float = 3.0,
) -> str:
    """Send a single control command to a running engine instance."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        payload = json.dumps({"command": command}) + "\n"
        sock.sendall(payload.encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b"\n" in data:
                break
        raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
        if not raw:
            return ""
        try:
            parsed = json.loads(raw)
            return str(parsed.get("output", ""))
        except json.JSONDecodeError:
            return raw
