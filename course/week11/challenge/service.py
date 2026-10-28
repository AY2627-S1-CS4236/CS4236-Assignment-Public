"""Stateful intercepted PKI relay exchange for the Week 11 MITM game."""

from __future__ import annotations

from dataclasses import dataclass
import secrets
import threading
import time

from educrypto import dh, pki
from educrypto.hashing import sponge_hash
from educrypto.pki_helpers import FFDHE2048, Certificate

if __package__:
    from . import _protocol
else:
    import _protocol

Session = _protocol.Session


SUITE_NAME = "pki-ffdhe2048-schnorr-etm-v1"
SERVICE_NAME = "pki-relay-game"
SERVER_NAME = "vault.course.test"
WINS_REQUIRED = 1
STAGE_SERVER_HELLO = "server_hello"
STAGE_CLIENT_ACCEPT = "client_accept"
STAGE_RELAY_TO_SERVER = "relay_to_server"
STAGE_RELAY_TO_CLIENT = "relay_to_client"
STAGE_GUESS = "guess"
STAGE_COMPLETE = "complete"


class GameError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def _hash(data: bytes) -> bytes:
    return sponge_hash(data, c=8, digest_length=32, rounds=20)


@dataclass(frozen=True, slots=True)
class GameView:
    game_id: str
    attempt_id: str
    stage: str
    client_hello: dict[str, str]
    root_public_key: dh.DHPublicKey
    certificate: Certificate
    compromised_root_signing_private_key: int
    wins: int
    complete: bool


@dataclass(frozen=True, slots=True)
class ActionResult:
    accepted: bool
    game: GameView
    server_response: dict[str, object] | None = None
    record: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class GuessResult:
    correct: bool
    game: GameView
    secret: str | None


@dataclass(slots=True)
class _Game:
    game_id: str
    attempt_id: str
    stage: str
    client_hello: dict[str, str]
    client_private_key: dh.DHPrivateKey
    server_signing_private_key: dh.DHPrivateKey
    certificate: Certificate
    server_session: Session | None = None
    client_session: Session | None = None
    first_client_message: bytes | None = None
    first_server_message: bytes | None = None
    second_client_message: bytes | None = None


class MitmGameService:
    """Own CA credentials, endpoint sessions, game stages, and the startup secret."""

    def __init__(self, secret: str) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("the startup secret must be a nonempty string")
        self._secret = secret
        self._lock = threading.Lock()
        self._games: dict[str, _Game] = {}

        self.root_public_key, self._root_private = dh.generate_keypair(FFDHE2048)

    def create_game(self) -> GameView:
        with self._lock:
            game_id = f"game_{secrets.token_hex(16)}"
            game = self._new_attempt(game_id)
            self._games[game_id] = game
            return self._view(game)

    def reset_game(self, game_id: str, attempt_id: str) -> GameView:
        with self._lock:
            game = self._get_game(game_id)
            self._require_attempt(game, attempt_id)
            replacement = self._new_attempt(game_id)
            self._games[game_id] = replacement
            return self._view(replacement)

    def contact_server(
        self, game_id: str, attempt_id: str, client_hello: dict[str, str]
    ) -> ActionResult:
        with self._lock:
            game = self._require_stage(game_id, attempt_id, STAGE_SERVER_HELLO)
            try:
                response, session = _protocol.create_server_hello(
                    client_hello,
                    game.server_signing_private_key,
                    game.certificate,
                )
            except (KeyError, TypeError, ValueError):
                return self._fail(game)
            game.server_session = session
            game.stage = STAGE_CLIENT_ACCEPT
            return ActionResult(True, self._view(game), server_response=response)

    def contact_client(
        self, game_id: str, attempt_id: str, response: dict[str, object]
    ) -> ActionResult:
        with self._lock:
            game = self._require_stage(game_id, attempt_id, STAGE_CLIENT_ACCEPT)
            session = _protocol.accept_server_hello(
                game.client_hello,
                game.client_private_key,
                response,
                self.root_public_key,
                now=int(time.time()),
            )
            if session is None:
                return self._fail(game)
            game.client_session = session
            game.first_client_message = secrets.token_bytes(32)
            record = _protocol.send_message(session, game.first_client_message)
            game.stage = STAGE_RELAY_TO_SERVER
            return ActionResult(True, self._view(game), record=record)

    def relay_to_server(
        self, game_id: str, attempt_id: str, record: dict[str, str]
    ) -> ActionResult:
        with self._lock:
            game = self._require_stage(game_id, attempt_id, STAGE_RELAY_TO_SERVER)
            if game.server_session is None:
                raise RuntimeError("server exchange was not initialized")
            plaintext = _protocol.receive_message(game.server_session, record)
            if plaintext is None:
                return self._fail(game)
            server_nonce = secrets.token_bytes(32)
            game.first_server_message = _hash(plaintext + server_nonce)
            server_record = _protocol.send_message(
                game.server_session, game.first_server_message
            )
            game.stage = STAGE_RELAY_TO_CLIENT
            return ActionResult(True, self._view(game), record=server_record)

    def relay_to_client(
        self, game_id: str, attempt_id: str, record: dict[str, str]
    ) -> ActionResult:
        with self._lock:
            game = self._require_stage(game_id, attempt_id, STAGE_RELAY_TO_CLIENT)
            if game.client_session is None:
                raise RuntimeError("client exchange was not initialized")
            plaintext = _protocol.receive_message(game.client_session, record)
            if plaintext is None:
                return self._fail(game)
            client_new_nonce = secrets.token_bytes(32)
            game.second_client_message = _hash(plaintext + client_new_nonce)
            client_record = _protocol.send_message(
                game.client_session, game.second_client_message
            )
            game.stage = STAGE_GUESS
            return ActionResult(True, self._view(game), record=client_record)

    def guess(
        self, game_id: str, attempt_id: str, message: bytes
    ) -> GuessResult:
        with self._lock:
            game = self._require_stage(game_id, attempt_id, STAGE_GUESS)
            if game.second_client_message is None:
                raise RuntimeError("second client message was not generated")
            if message == game.second_client_message:
                game.stage = STAGE_COMPLETE
                return GuessResult(True, self._view(game), self._secret)
            replacement = self._replace(game)
            return GuessResult(False, self._view(replacement), None)

    def _new_attempt(self, game_id: str) -> _Game:
        public, private = dh.generate_keypair(FFDHE2048)
        now = int(time.time())
        certificate = pki.issue_certificate(
            self._root_private, SERVER_NAME, public, now + 24 * 60 * 60,
        )
        client_hello, client_private_key = _protocol.create_client_hello(SERVER_NAME)
        return _Game(
            game_id=game_id,
            attempt_id=f"attempt_{secrets.token_hex(16)}",
            stage=STAGE_SERVER_HELLO,
            client_hello=client_hello,
            client_private_key=client_private_key,
            server_signing_private_key=private,
            certificate=certificate,
        )

    def _replace(self, game: _Game) -> _Game:
        replacement = self._new_attempt(game.game_id)
        self._games[game.game_id] = replacement
        return replacement

    def _fail(self, game: _Game) -> ActionResult:
        return ActionResult(False, self._view(self._replace(game)))

    def _get_game(self, game_id: str) -> _Game:
        try:
            return self._games[game_id]
        except KeyError as error:
            raise GameError("game was not found", 404) from error

    @staticmethod
    def _require_attempt(game: _Game, attempt_id: str) -> None:
        if game.attempt_id != attempt_id:
            raise GameError("attempt is stale; use the current game view", 409)

    def _require_stage(self, game_id: str, attempt_id: str, stage: str) -> _Game:
        game = self._get_game(game_id)
        self._require_attempt(game, attempt_id)
        if game.stage != stage:
            raise GameError("action is unavailable at the current stage", 409)
        return game

    def _view(self, game: _Game) -> GameView:
        return GameView(
            game_id=game.game_id,
            attempt_id=game.attempt_id,
            stage=game.stage,
            client_hello=dict(game.client_hello),
            root_public_key=self.root_public_key,
            certificate=game.certificate,
            compromised_root_signing_private_key=self._root_private.exponent,
            wins=int(game.stage == STAGE_COMPLETE),
            complete=game.stage == STAGE_COMPLETE,
        )
