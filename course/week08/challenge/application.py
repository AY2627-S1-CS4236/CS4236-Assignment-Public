"""Flask routes for the Week 08 ElGamal CPA game."""

from __future__ import annotations

import os
import re

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType

from educrypto.dh import DHParameters

if __package__:
    from .service import (
        SUITE_NAME,
        WINS_REQUIRED,
        Ciphertext,
        ElGamalGameService,
        GameError,
        GameView,
    )
else:
    from service import (
        SUITE_NAME,
        WINS_REQUIRED,
        Ciphertext,
        ElGamalGameService,
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


def _decimal_integer(value: object, field_name: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+", value) is None:
        raise GameError(f"{field_name} must be a decimal integer string")
    try:
        return int(value, 10)
    except ValueError as error:
        raise GameError(f"{field_name} is too large") from error


def _game_payload(view: GameView) -> dict[str, object]:
    return {
        "game_id": view.game_id,
        "suite": SUITE_NAME,
        "p": str(view.p),
        "g": str(view.g),
        "h": str(view.public_key),
        "wins": view.wins,
        "wins_required": WINS_REQUIRED,
        "complete": view.complete,
    }


def _ciphertext_payload(output: Ciphertext) -> dict[str, str]:
    return {"c1": str(output.c1), "c2": str(output.c2)}


def create_app(
    secret: str | None = None, *, parameters: DHParameters | None = None
) -> Flask:
    """Build the game; tests may inject a smaller group for lifecycle checks."""

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/assets",
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    service = ElGamalGameService(
        _environment_secret() if secret is None else secret,
        parameters,
    )
    app.extensions["elgamal_game_service"] = service

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "elgamal-cpa-game"})

    @app.post("/api/v1/games")
    def create_game():
        return jsonify(_game_payload(service.create_game())), 201

    @app.post("/api/v1/games/<game_id>/reset")
    def reset_game(game_id: str):
        return jsonify(_game_payload(service.reset_game(game_id)))

    @app.post("/api/v1/games/<game_id>/challenge")
    def create_challenge(game_id: str):
        value = _json_object()
        output = service.create_challenge(
            game_id,
            _decimal_integer(value.get("left"), "left"),
            _decimal_integer(value.get("right"), "right"),
        )
        return jsonify(_ciphertext_payload(output)), 201

    @app.post("/api/v1/games/<game_id>/guess")
    def submit_guess(game_id: str):
        value = _json_object()
        result = service.guess(game_id, value.get("guess"))
        payload: dict[str, object] = {
            "correct": result.correct,
            "wins": result.wins,
            "wins_required": WINS_REQUIRED,
            "complete": result.secret is not None,
        }
        if result.public_key is not None:
            payload["h"] = str(result.public_key)
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
