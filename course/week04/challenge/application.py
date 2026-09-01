"""Flask application factory and HTTP routes for the EUF-CMA game."""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType

if __package__:
    from .service import EufCmaGameService, GameError, GameView, TagSuiteFactory
else:
    from service import EufCmaGameService, GameError, GameView, TagSuiteFactory


MAX_BODY_BYTES = 1_000_000
SECRET_ENVIRONMENT_VARIABLE = "SECRET"


def _environment_secret() -> str:
    try:
        return os.environ[SECRET_ENVIRONMENT_VARIABLE]
    except KeyError as error:
        raise RuntimeError(f"{SECRET_ENVIRONMENT_VARIABLE} is not set") from error


def _json_object() -> dict[str, object]:
    if not request.is_json:
        raise BadRequest("request body must be JSON")
    value = request.get_json()
    if not isinstance(value, dict):
        raise BadRequest("request body must be an object")
    return value


def _hex_bytes(value: object, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise GameError(f"{field_name} must be a hexadecimal string")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise GameError(f"{field_name} must be valid hexadecimal") from error


def _game_payload(game: GameView) -> dict[str, object]:
    return {
        "game_id": game.game_id,
        "suite": {
            "name": game.suite.name,
            "tag_group_bytes": game.suite.tag_group_bytes,
            "tag_bytes": game.suite.tag_bytes,
        },
        "wins": game.wins,
        "wins_required": game.wins_required,
    }


def create_app(
    secret: str | None = None,
    suite_factory: TagSuiteFactory | None = None,
) -> Flask:
    """Build a configured EUF-CMA game application."""

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/assets",
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    service = EufCmaGameService(
        _environment_secret() if secret is None else secret,
        suite_factory=suite_factory,
    )
    app.extensions["euf_cma_game_service"] = service

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "euf-cma-game"})

    @app.post("/api/v1/games")
    def create_game():
        return jsonify(_game_payload(service.create_game())), 201

    @app.post("/api/v1/games/<game_id>/reset")
    def reset_game(game_id: str):
        return jsonify(_game_payload(service.reset_game(game_id)))

    @app.post("/api/v1/games/<game_id>/oracle")
    def tag_with_oracle(game_id: str):
        value = _json_object()
        tag = service.tag_with_oracle(
            game_id,
            _hex_bytes(value.get("message_hex"), "message_hex"),
        )
        return jsonify({"tag_hex": tag.hex()})

    @app.post("/api/v1/games/<game_id>/forge")
    def submit_forgery(game_id: str):
        value = _json_object()
        result = service.submit_forgery(
            game_id,
            _hex_bytes(value.get("message_hex"), "message_hex"),
            _hex_bytes(value.get("tag_hex"), "tag_hex"),
        )
        payload: dict[str, object] = {
            "valid": result.valid,
            "fresh": result.fresh,
            "wins": result.wins,
            "wins_required": result.wins_required,
            "complete": result.secret is not None,
        }
        if result.secret is not None:
            payload["secret"] = result.secret
        return jsonify(payload)

    @app.errorhandler(GameError)
    def game_error(error: GameError):
        return jsonify({"error": str(error)}), error.status_code

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
