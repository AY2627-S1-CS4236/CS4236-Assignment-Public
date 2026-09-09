"""Flask application factory and HTTP routes for the collision game."""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType

if __package__:
    from .service import (
        ROUNDS,
        STATE_BYTES,
        SUITE_NAME,
        TARGETS,
        WINS_REQUIRED,
        CollisionGameService,
        GameError,
        GameView,
    )
else:
    from service import (
        ROUNDS,
        STATE_BYTES,
        SUITE_NAME,
        TARGETS,
        WINS_REQUIRED,
        CollisionGameService,
        GameError,
        GameView,
    )


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
            "name": SUITE_NAME,
            "state_bytes": STATE_BYTES,
            "rounds": ROUNDS,
            "padding": "pad10*1-msb",
        },
        "hashes": [
            {
                "hash_id": target.hash_id,
                "capacity_bytes": target.capacity_bytes,
                "rate_bytes": target.rate_bytes,
                "digest_bytes": target.digest_bytes,
                "solved": target.hash_id in game.solved,
            }
            for target in TARGETS
        ],
        "wins": len(game.solved),
        "wins_required": WINS_REQUIRED,
        "complete": len(game.solved) == WINS_REQUIRED,
    }


def create_app(
    secret: str | None = None,
) -> Flask:
    """Build a configured two-target sponge collision application."""

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/assets",
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    service = CollisionGameService(_environment_secret() if secret is None else secret)
    app.extensions["collision_game_service"] = service

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "sponge-collision-game"})

    @app.post("/api/v1/games")
    def create_game():
        return jsonify(_game_payload(service.create_game())), 201

    @app.post("/api/v1/games/<game_id>/reset")
    def reset_game(game_id: str):
        return jsonify(_game_payload(service.reset_game(game_id)))

    @app.post("/api/v1/games/<game_id>/hash")
    def hash_message(game_id: str):
        value = _json_object()
        digest = service.hash_message(
            game_id,
            value.get("hash_id"),
            _hex_bytes(value.get("message_hex"), "message_hex"),
        )
        return jsonify({"hash_id": value["hash_id"], "digest_hex": digest.hex()})

    @app.post("/api/v1/games/<game_id>/collide")
    def submit_collision(game_id: str):
        value = _json_object()
        result = service.submit_collision(
            game_id,
            value.get("hash_id"),
            _hex_bytes(value.get("left_hex"), "left_hex"),
            _hex_bytes(value.get("right_hex"), "right_hex"),
        )
        payload: dict[str, object] = {
            "hash_id": result.hash_id,
            "valid": result.valid,
            "distinct": result.distinct,
            "left_digest_hex": result.left_digest.hex(),
            "right_digest_hex": result.right_digest.hex(),
            "wins": result.wins,
            "wins_required": WINS_REQUIRED,
            "complete": result.wins == WINS_REQUIRED,
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
