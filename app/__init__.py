"""Application factory for the AI Cyber Threat Detector."""
from __future__ import annotations

import logging

from flask import Flask

from .config import Config

__all__ = ["Config", "create_app"]


def create_app(config: Config | None = None) -> Flask:
    """Build a configured Flask app.

    Taking config as an argument (rather than reading globals at import time)
    is what lets the test-suite point the app at a temporary dataset.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app = Flask(__name__)
    cfg = config or Config()
    cfg.ensure_dirs()
    app.config["APP_CONFIG"] = cfg
    app.config["JSON_SORT_KEYS"] = False

    from .routes import bp

    app.register_blueprint(bp)
    return app
