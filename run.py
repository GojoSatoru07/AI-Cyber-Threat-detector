"""Development entry point: python run.py

For anything resembling production use a real WSGI server instead:
    gunicorn "app:create_app()" --bind 0.0.0.0:5000
"""
from __future__ import annotations

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    config = app.config["APP_CONFIG"]
    # Bind to loopback by default; this app has no authentication, so exposing
    # it on 0.0.0.0 must be a deliberate choice.
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=config.debug,
    )
