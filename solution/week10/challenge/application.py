"""HTTP parsing and serialization for the Week 10 Schnorr game."""

from __future__ import annotations

import os
import re

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType

from educrypto.dh import DHParameters
from educrypto.schnorr import SchnorrSignature

if __package__:
    from .service import SUITE_NAME, WINS_REQUIRED, GameError, GameView, SchnorrGameService
else:
    from service import SUITE_NAME, WINS_REQUIRED, GameError, GameView, SchnorrGameService


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


def _decimal_integer(value: object, field_name: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+", value) is None:
        raise GameError(f"{field_name} must be a nonnegative decimal integer string")
    try:
        return int(value, 10)
    except ValueError as error:
        raise GameError(f"{field_name} is too large") from error


def _game_payload(game: GameView) -> dict[str, object]:
    return {
        "game_id": game.game_id,
        "suite": SUITE_NAME,
        "p": str(game.parameters.p),
        "q": str(game.parameters.q),
        "g": str(game.parameters.g),
        "y": str(game.public_key),
        "queries": game.queries,
        "wins": game.wins,
        "wins_required": WINS_REQUIRED,
        "complete": game.complete,
    }


def create_app(
    secret: str | None = None, *, parameters: DHParameters | None = None
) -> Flask:
    app = Flask(
        __name__, template_folder="templates", static_folder="static",
        static_url_path="/assets",
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    service = SchnorrGameService(
        _environment_secret() if secret is None else secret, parameters
    )
    app.extensions["schnorr_game_service"] = service

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "schnorr-euf-cma-game"})

    @app.post("/api/v1/games")
    def create_game():
        return jsonify(_game_payload(service.create_game())), 201

    @app.post("/api/v1/games/<game_id>/reset")
    def reset_game(game_id: str):
        return jsonify(_game_payload(service.reset_game(game_id)))

    @app.post("/api/v1/games/<game_id>/oracle")
    def sign_with_oracle(game_id: str):
        value = _json_object()
        result = service.sign_with_oracle(
            game_id, _hex_bytes(value.get("message_hex"), "message_hex")
        )
        return jsonify({
            "R": str(result.signature.R), "s": str(result.signature.s),
            "queries": result.queries,
        })

    @app.post("/api/v1/games/<game_id>/forge")
    def submit_forgery(game_id: str):
        value = _json_object()
        result = service.submit_forgery(
            game_id,
            _hex_bytes(value.get("message_hex"), "message_hex"),
            SchnorrSignature(
                _decimal_integer(value.get("R"), "R"),
                _decimal_integer(value.get("s"), "s"),
            ),
        )
        payload = {
            "valid": result.valid, "fresh": result.fresh,
            "game": _game_payload(result.game),
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
        return jsonify({"error": "request body must be a valid JSON object"}), 400

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
