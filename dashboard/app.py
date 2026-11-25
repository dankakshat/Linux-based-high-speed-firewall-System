"""Read-only Flask telemetry dashboard for XDP-Engine."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from xdp_engine.storage import Storage


def create_app(db_path: str | Path | None = None) -> Flask:
    """Create and configure the Flask dashboard application."""
    template_dir = Path(__file__).resolve().parent / "templates"
    app = Flask(__name__, template_folder=str(template_dir))

    resolved_db = Path(
        db_path
        or os.environ.get("XDP_DB_PATH")
        or (Path(__file__).resolve().parent.parent / "engine.db")
    )
    storage = Storage(resolved_db)
    app.config["STORAGE"] = storage

    @app.get("/")
    def index() -> str:
        if request.args.get("showcase") == "1":
            return render_template("showcase.html")
        return render_template("index.html")

    @app.get("/api/status")
    def api_status():
        return jsonify(storage.get_status())

    @app.get("/api/alerts")
    def api_alerts():
        limit = request.args.get("limit", default=40, type=int)
        return jsonify(storage.get_alerts(limit=max(1, min(limit, 200))))

    @app.get("/api/blocks")
    def api_blocks():
        return jsonify(storage.get_blocked_ips())

    @app.get("/api/feed")
    def api_feed():
        limit = request.args.get("limit", default=50, type=int)
        return jsonify(storage.get_feed(limit=max(1, min(limit, 200))))

    @app.get("/api/overview")
    def api_overview():
        return jsonify(
            {
                "status": storage.get_status(),
                "alerts": storage.get_alerts(limit=25),
                "blocks": storage.get_blocked_ips(),
                "feed": storage.get_feed(limit=40),
            }
        )

    return app


def main() -> None:
    """Run the Flask telemetry server."""
    port = int(os.environ.get("XDP_DASHBOARD_PORT", "5000"))
    app = create_app()
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
