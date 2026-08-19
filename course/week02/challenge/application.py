"""Flask application factory and HTTP routes for SeedSafe."""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType

if __package__:
    from .service import BackupService, StoredBackup
else:
    from service import BackupService, StoredBackup


MAX_BODY_BYTES = 1_000_000
SECRET_ENVIRONMENT_VARIABLE = "SECRET"


def _environment_secret() -> str:
    try:
        return os.environ[SECRET_ENVIRONMENT_VARIABLE]
    except KeyError as error:
        raise RuntimeError(
            f"{SECRET_ENVIRONMENT_VARIABLE} is not set"
        ) from error


def _public_record(record: StoredBackup) -> dict[str, str]:
    return {
        "record_id": record.record_id,
        "created_at": record.created_at,
        "algorithm": "spn-128-ecb-v1",
        "ciphertext_hex": record.ciphertext.hex(),
    }


def _json_object() -> dict[str, object]:
    if not request.is_json:
        raise BadRequest("request body must be JSON")
    value = request.get_json()
    if not isinstance(value, dict):
        raise BadRequest("request body must be an object")
    return value


def create_app(secret: str | None = None) -> Flask:
    """Build a configured SeedSafe Flask application."""

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/assets",
    )
    # Reject oversized requests before parsing their JSON bodies.
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    service = BackupService(_environment_secret() if secret is None else secret)
    app.extensions["backup_service"] = service

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "seedsafe"})

    @app.get("/api/v1/backups")
    def list_backups():
        return jsonify(
            {"backups": [_public_record(record) for record in service.list_backups()]}
        )

    @app.post("/api/v1/backups")
    def create_backup():
        value = _json_object()
        text = value.get("text")
        if not isinstance(text, str) or not text:
            return jsonify({"error": "backup text must not be empty"}), 400

        record, seed = service.store(text)
        result = _public_record(record)
        # The seed is returned once but is not retained in the public record.
        result["seed_hex"] = seed.hex()
        return jsonify(result), 201

    @app.post("/api/v1/backups/restore")
    def restore_backup():
        value = _json_object()
        record_id = value.get("record_id")
        seed_hex = value.get("seed_hex")
        if not isinstance(record_id, str) or not isinstance(seed_hex, str):
            return jsonify({"error": "record ID and recovery seed are required"}), 400

        try:
            seed = bytes.fromhex(seed_hex)
            text = service.restore(record_id, seed)
        except ValueError:
            return jsonify({"error": "backup could not be restored"}), 400
        return jsonify({"text": text})

    # Return JSON consistently for both API and routing errors.
    @app.errorhandler(BadRequest)
    @app.errorhandler(UnsupportedMediaType)
    def bad_request(_error):
        return jsonify({"error": "request body must be valid JSON"}), 400

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return jsonify({"error": "request body is too large"}), 413

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "resource not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify({"error": "method not allowed"}), 405

    return app
