"""Secure Student Portal: application factory."""
from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, make_response, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db, security
from .config import Config


def create_app(test_config=None) -> Flask:
    app = Flask(__name__, instance_path=str(Config.INSTANCE_DIR), instance_relative_config=False)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    extra_hosts = os.environ.get("PORTAL_ALLOWED_HOSTS")
    if extra_hosts:
        app.config["ALLOWED_HOSTS"] = tuple(h.strip().lower() for h in extra_hosts.split(",") if h.strip())

    # Secrets come from the environment or a private file, never from source code.
    if not all(app.config.get(k) for k in ("SECRET_KEY", "JWT_SECRET", "FERNET_KEY", "WEBHOOK_SECRET")):
        loaded = security.load_secrets(app.instance_path)
        for key, value in loaded.items():
            if not app.config.get(key):
                app.config[key] = value

    if app.config["BEHIND_PROXY"]:
        # Behind Nginx: trust exactly one proxy hop for client IP, scheme and host.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    _configure_logging(app)
    db.init_app(app)
    app.extensions["limiter"] = security.RateLimiter()
    security.init_app(app)

    with app.app_context():
        db.init_db()

    from .routes import admin, api, auth, portal, staff
    for module in (auth, portal, staff, admin, api):
        app.register_blueprint(module.bp)

    _register_error_handlers(app)
    return app


def _configure_logging(app: Flask) -> None:
    logger = logging.getLogger("portal")
    logger.setLevel(logging.INFO)
    if app.config["LOG_TO_FILE"] and not logger.handlers:
        handler = logging.FileHandler(app.config["LOG_FILE"])
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)


_MESSAGES = {
    400: ("Bad request", "The request could not be processed."),
    403: ("Access denied", "You do not have permission to do that."),
    404: ("Not found", "That page or record does not exist."),
    405: ("Method not allowed", "That action is not supported here."),
    413: ("Request too large", "The request was too big."),
    429: ("Too many requests", "Please slow down and try again shortly."),
    500: ("Something went wrong", "An internal error occurred. It has been logged."),
}


def _register_error_handlers(app: Flask) -> None:
    def handle(err):
        code = getattr(err, "code", 500) or 500
        title, message = _MESSAGES.get(code, ("Error", "The request failed."))
        if request.path.startswith("/api/"):
            response = jsonify(error=title.lower().replace(" ", "_"))
            response.status_code = code
        else:
            response = make_response(render_template("error.html", code=code, title=title, message=message), code)
        retry = getattr(err, "retry_after", None)
        if retry:
            response.headers["Retry-After"] = str(retry)
        return response

    for code in _MESSAGES:
        app.register_error_handler(code, handle)
