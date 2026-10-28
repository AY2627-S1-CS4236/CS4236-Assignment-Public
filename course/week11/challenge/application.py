"""HTTP transport and JSON validation for the Week 11 MITM game."""

from __future__ import annotations

import os
import re
from typing import Any

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType

from educrypto.pki_helpers import FFDHE2048, Certificate

if __package__:
    from ._protocol import GROUP_ID
    from .service import (
        SERVICE_NAME,
        SUITE_NAME,
        WINS_REQUIRED,
        ActionResult,
        GameError,
        GameView,
        GuessResult,
        MitmGameService,
    )
else:
    from _protocol import GROUP_ID
    from service import (
        SERVICE_NAME,
        SUITE_NAME,
        WINS_REQUIRED,
        ActionResult,
        GameError,
        GameView,
        GuessResult,
        MitmGameService,
    )


MAX_BODY_BYTES = 1_000_000
SECRET_ENVIRONMENT_VARIABLE = "SECRET"


def _environment_secret() -> str:
    try:
        return os.environ[SECRET_ENVIRONMENT_VARIABLE]
    except KeyError as error:
        raise RuntimeError(f"{SECRET_ENVIRONMENT_VARIABLE} is not set") from error


def _json_object(fields: set[str]) -> dict[str, object]:
    if not request.is_json:
        raise BadRequest("request body must be JSON")
    value = request.get_json()
    if not isinstance(value, dict) or set(value) != fields:
        raise BadRequest("request body has the wrong fields")
    return value


def _attempt(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"attempt_[0-9a-f]{32}", value) is None:
        raise GameError("attempt_id must be an attempt identifier")
    return value


def _checked(validator, value: object, field_name: str):
    try:
        return validator(value)
    except (TypeError, ValueError, KeyError, OverflowError) as error:
        raise GameError(f"invalid {field_name}: {error}") from error


def _object(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"expected object with fields {', '.join(sorted(keys))}")
    return value


def _decimal_text(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or re.fullmatch(r"[0-9]+", value) is None
    ):
        raise ValueError(f"{field} must be a decimal string")


def _hex_text(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a hexadecimal string")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{field} must be a hexadecimal string") from error


def _signature(value: Any) -> dict[str, Any]:
    obj = _object(value, {"R", "s"})
    _decimal_text(obj["R"], "R")
    _decimal_text(obj["s"], "s")
    return obj


def _certificate_json(value: Certificate) -> dict[str, Any]:
    return {
        "hostname": value.hostname,
        "public_key": str(value.public_key.value),
        "expires_at": value.expires_at,
        "signature": {"R": str(value.signature.R), "s": str(value.signature.s)},
    }


def _certificate(value: Any) -> dict[str, Any]:
    obj = _object(value, {"hostname", "public_key", "expires_at", "signature"})
    if not isinstance(obj["hostname"], str):
        raise ValueError("hostname must be a string")
    if type(obj["expires_at"]) is not int:
        raise ValueError("expires_at must be an integer")
    _decimal_text(obj["public_key"], "public_key")
    _signature(obj["signature"])
    return obj


def _client_hello(value: Any) -> dict[str, Any]:
    obj = _object(value, {"server_name", "key_share"})
    if not isinstance(obj["server_name"], str):
        raise ValueError("server_name must be a string")
    _decimal_text(obj["key_share"], "key_share")
    return obj


def _server_response(value: Any) -> dict[str, Any]:
    obj = _object(value, {"key_share", "certificate", "signature"})
    _decimal_text(obj["key_share"], "key_share")
    _certificate(obj["certificate"])
    _signature(obj["signature"])
    return obj


def _record(value: Any) -> dict[str, Any]:
    obj = _object(value, {"direction", "sequence", "iv_hex", "ciphertext_hex", "tag_hex"})
    if obj["direction"] not in ("0", "1"):
        raise ValueError("direction must be '0' or '1'")
    _decimal_text(obj["sequence"], "sequence")
    _hex_text(obj["iv_hex"], "iv_hex")
    _hex_text(obj["ciphertext_hex"], "ciphertext_hex")
    _hex_text(obj["tag_hex"], "tag_hex")
    return obj


def _message(value: object) -> bytes:
    if not isinstance(value, str) or len(value) > 8192:
        raise GameError("message_hex must be a hexadecimal string of at most 32 bytes")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise GameError("message_hex must be valid hexadecimal") from error
    if len(decoded) > 32:
        raise GameError("message_hex must contain at most 32 bytes")
    return decoded


def _game_payload(game: GameView) -> dict[str, object]:
    return {
        "game_id": game.game_id,
        "attempt_id": game.attempt_id,
        "stage": game.stage,
        "suite": SUITE_NAME,
        "group": {
            "id": GROUP_ID,
            "p": str(FFDHE2048.p),
            "q": str(FFDHE2048.q),
            "g": str(FFDHE2048.g),
        },
        "client_hello": game.client_hello,
        "root_public_key": str(game.root_public_key.value),
        "certificate": _certificate_json(game.certificate),
        "compromised_root_signing_private_key": str(
            game.compromised_root_signing_private_key
        ),
        "wins": game.wins,
        "wins_required": WINS_REQUIRED,
        "complete": game.complete,
    }


def _action_payload(result: ActionResult) -> dict[str, object]:
    payload: dict[str, object] = {
        "accepted": result.accepted,
        "game": _game_payload(result.game),
    }
    if result.server_response is not None:
        payload["server_response"] = result.server_response
    if result.record is not None:
        payload["record"] = result.record
    return payload


def _guess_payload(result: GuessResult) -> dict[str, object]:
    payload: dict[str, object] = {
        "correct": result.correct,
        "game": _game_payload(result.game),
    }
    if result.secret is not None:
        payload["secret"] = result.secret
    return payload


def create_app(secret: str | None = None) -> Flask:
    app = Flask(
        __name__, template_folder="templates", static_folder="static",
        static_url_path="/assets",
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    service = MitmGameService(_environment_secret() if secret is None else secret)
    app.extensions["mitm_game_service"] = service

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": SERVICE_NAME})

    @app.post("/api/v1/games")
    def create_game():
        return jsonify(_game_payload(service.create_game())), 201

    @app.post("/api/v1/games/<game_id>/reset")
    def reset_game(game_id: str):
        value = _json_object({"attempt_id"})
        return jsonify(_game_payload(service.reset_game(game_id, _attempt(value["attempt_id"]))))

    @app.post("/api/v1/games/<game_id>/server-hello")
    def server_hello(game_id: str):
        value = _json_object({"attempt_id", "client_hello"})
        result = service.contact_server(
            game_id,
            _attempt(value["attempt_id"]),
            _checked(_client_hello, value["client_hello"], "client_hello"),
        )
        return jsonify(_action_payload(result))

    @app.post("/api/v1/games/<game_id>/client-accept")
    def client_accept(game_id: str):
        value = _json_object({"attempt_id", "server_response"})
        result = service.contact_client(
            game_id,
            _attempt(value["attempt_id"]),
            _checked(_server_response, value["server_response"], "server_response"),
        )
        return jsonify(_action_payload(result))

    @app.post("/api/v1/games/<game_id>/relay-to-server")
    def relay_to_server(game_id: str):
        value = _json_object({"attempt_id", "record"})
        result = service.relay_to_server(
            game_id,
            _attempt(value["attempt_id"]),
            _checked(_record, value["record"], "record"),
        )
        return jsonify(_action_payload(result))

    @app.post("/api/v1/games/<game_id>/relay-to-client")
    def relay_to_client(game_id: str):
        value = _json_object({"attempt_id", "record"})
        result = service.relay_to_client(
            game_id,
            _attempt(value["attempt_id"]),
            _checked(_record, value["record"], "record"),
        )
        return jsonify(_action_payload(result))

    @app.post("/api/v1/games/<game_id>/guess")
    def guess(game_id: str):
        value = _json_object({"attempt_id", "message_hex"})
        result = service.guess(
            game_id, _attempt(value["attempt_id"]), _message(value["message_hex"])
        )
        return jsonify(_guess_payload(result))

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
