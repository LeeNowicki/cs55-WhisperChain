"""FastAPI application factory."""

from pathlib import Path

from fastapi import FastAPI

from whisperchain.server.alerts import AlertEngine
from whisperchain.server.audit import AuditLog, load_signing_key
from whisperchain.server.config import ServerPaths, build_config
from whisperchain.server.ratelimit import build_limiters
from whisperchain.server.rejections import RejectionTracker
from whisperchain.server.routes import accounts, admin, audit, keys, messages, moderation, tokens


def create_app(data_dir: Path, config: dict | None = None) -> FastAPI:
    """Build a new app bound to one data directory.

    A factory (instead of a global `app`) lets every test build a fresh,
    isolated server on its own temporary directory.
    """
    paths = ServerPaths(Path(data_dir))
    if not paths.db.exists():
        raise RuntimeError(
            f"no database at {paths.db}; run `python -m whisperchain.server init` first"
        )

    # Hide the interactive docs: they would be extra unauthenticated routes.
    app = FastAPI(title="WhisperChain+", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.paths = paths
    app.state.config = build_config(config)
    app.state.jwt_secret = paths.jwt_secret.read_bytes()
    app.state.limiters = build_limiters(app.state.config)
    app.state.challenges = accounts.ChallengeStore()
    app.state.audit = AuditLog(load_signing_key(paths.audit_key))
    app.state.rejections = RejectionTracker(
        app.state.config["spend_reject_audit_interval_seconds"],
        app.state.config["alert_rejection_burst_window_seconds"],
    )
    app.state.alerts = AlertEngine(app.state.config, app.state.rejections)
    app.state.audit.on_append = app.state.alerts.after_append

    @app.get("/health")
    def health():
        return {"status": "ok"}

    app.include_router(accounts.router)
    app.include_router(admin.router)
    app.include_router(audit.router)
    app.include_router(keys.router)
    app.include_router(tokens.router)
    app.include_router(messages.router)
    app.include_router(moderation.router)
    return app
