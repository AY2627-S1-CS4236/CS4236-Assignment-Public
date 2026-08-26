"""Flask application factory and HTTP routes for the R-CPA game."""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType

if __package__:
    from .service import CipherSuiteFactory, GameError, GameView, RcpaGameService
else:
    from service import CipherSuiteFactory, GameError, GameView, RcpaGameService


MAX_BODY_BYTES = 1_000_000
SECRET_ENVIRONMENT_VARIABLE = "SECRET"


def _environment_secret() -> str:
    try:
        return os.environ[SECRET_ENVIRONMENT_VARIABLE]
    except KeyError as error:
        raise RuntimeError(
            f"{SECRET_ENVIRONMENT_VARIABLE} is not set"
        ) from error


def _json_object() -> dict[str, object]:
    if not request.is_json:
        raise BadRequest("request body must be JSON")
    value = request.get_json()
    if not isinstance(value, dict):
        raise BadRequest("request body must be an object")
    return value


def _hex_message(value: object, field_name: str) -> bytes:
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
            "ciphertext_group_bytes": game.suite.ciphertext_group_bytes,
        },
        "wins": game.wins,
        "wins_required": game.wins_required,
    }


def create_app(
    secret: str | None = None,
    suite_factory: CipherSuiteFactory | None = None,
) -> Flask:
    """Build a configured R-CPA game application."""

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/assets",
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    service = RcpaGameService(
        _environment_secret() if secret is None else secret,
        suite_factory=suite_factory,
    )
    app.extensions["rcpa_game_service"] = service

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "rcpa-game"})

    @app.post("/api/v1/games")
    def create_game():
        return jsonify(_game_payload(service.create_game())), 201

    @app.post("/api/v1/games/<game_id>/reset")
    def reset_game(game_id: str):
        return jsonify(_game_payload(service.reset_game(game_id)))

    @app.post("/api/v1/games/<game_id>/oracle")
    def encrypt_with_oracle(game_id: str):
        value = _json_object()
        result = service.encrypt_with_oracle(
            game_id,
            _hex_message(value.get("message_hex"), "message_hex"),
        )
        return jsonify(
            {
                "iv_hex": result.initialization_vector.hex(),
                "ciphertext_hex": result.ciphertext.hex(),
            }
        )

    @app.post("/api/v1/games/<game_id>/challenge")
    def create_challenge(game_id: str):
        value = _json_object()
        result = service.create_challenge(
            game_id,
            _hex_message(value.get("left_hex"), "left_hex"),
            _hex_message(value.get("right_hex"), "right_hex"),
        )
        return jsonify(
            {
                "iv_hex": result.initialization_vector.hex(),
                "ciphertext_hex": result.ciphertext.hex(),
            }
        ), 201

    @app.post("/api/v1/games/<game_id>/guess")
    def submit_guess(game_id: str):
        value = _json_object()
        result = service.guess(game_id, value.get("guess"))
        payload: dict[str, object] = {
            "correct": result.correct,
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
