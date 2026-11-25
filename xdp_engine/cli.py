"""Standalone CLI client for controlling a running XDP-Engine instance."""

from __future__ import annotations

import argparse
import sys

from .ipc import DEFAULT_IPC_HOST, DEFAULT_IPC_PORT, send_ipc_command


def main(argv: list[str] | None = None) -> int:
    """Send a control command over IPC to the running engine."""
    parser = argparse.ArgumentParser(description="XDP-Engine CLI controller")
    parser.add_argument("--host", default=DEFAULT_IPC_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_IPC_PORT)
    parser.add_argument("command", nargs="+", help="Command (e.g. mode enforce, list, stats)")
    args = parser.parse_args(argv)

    cmd_str = " ".join(args.command)
    try:
        output = send_ipc_command(cmd_str, host=args.host, port=args.port)
        if output:
            print(output)
        return 0
    except OSError as exc:
        print(f"Error connecting to XDP-Engine at {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
