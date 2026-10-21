"""Schnorr EUF-CMA game with a deliberately advancing nonce."""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import threading

from educrypto.dh import (
    DHParameters,
    DHPrivateKey,
    DHPublicKey,
    generate_keypair,
    generate_parameters,
)
from educrypto.hashing import sponge_hash
from educrypto.schnorr import SchnorrSignature, verify


WINS_REQUIRED = 1
NONCE_STEP = 10
MAX_MESSAGE_BYTES = 4096
SUITE_NAME = "schnorr-advancing-nonce-v1"


class GameError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class GameView:
    game_id: str
    parameters: DHParameters
    public_key: int
    queries: int
    wins: int
    complete: bool


@dataclass(frozen=True, slots=True)
class OracleResult:
    signature: SchnorrSignature
    queries: int


@dataclass(frozen=True, slots=True)
class ForgeryResult:
    valid: bool
    fresh: bool
    game: GameView
    secret: str | None


@dataclass(slots=True)
class _Game:
    game_id: str
    public_key: DHPublicKey
    private_key: DHPrivateKey
    nonce: int
    oracle_messages: set[bytes] = field(default_factory=set)
    queries: int = 0
    complete: bool = False


class SchnorrGameService:
    """Keep each key, nonce sequence, and exact-message history independent."""

    def __init__(self, secret: str, parameters: DHParameters | None = None) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("the startup secret must not be empty")
        self._secret = secret
        self.parameters = (
            generate_parameters(bits=256) if parameters is None else parameters
        )
        self._games: dict[str, _Game] = {}
        self._lock = threading.Lock()

    def create_game(self) -> GameView:
        with self._lock:
            game_id = f"game_{secrets.token_hex(16)}"
            public, private = generate_keypair(self.parameters)
            game = _Game(
                game_id, public, private, secrets.randbelow(self.parameters.q)
            )
            self._games[game_id] = game
            return self._view(game)

    def reset_game(self, game_id: str) -> GameView:
        with self._lock:
            game = self._game(game_id)
            self._refresh(game)
            return self._view(game)

    def sign_with_oracle(self, game_id: str, message: bytes) -> OracleResult:
        self._validate_message(message)
        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            p, q, g = self.parameters.p, self.parameters.q, self.parameters.g
            R = pow(g, game.nonce, p)
            width = (p.bit_length() + 7) // 8
            digest = sponge_hash(
                R.to_bytes(width, "big") + message,
                c=8,
                digest_length=32,
                rounds=20,
            )
            r = int.from_bytes(digest, "big") % q
            signature = SchnorrSignature(
                R, (game.nonce + r * game.private_key.exponent) % q
            )
            game.nonce = (game.nonce + NONCE_STEP) % q
            game.oracle_messages.add(message)
            game.queries += 1
            return OracleResult(signature, game.queries)

    def submit_forgery(
        self, game_id: str, message: bytes, signature: SchnorrSignature
    ) -> ForgeryResult:
        self._validate_message(message)
        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            fresh = message not in game.oracle_messages
            valid = fresh and verify(game.public_key, message, signature)
            if valid:
                game.complete = True
            else:
                self._refresh(game)
            return ForgeryResult(
                valid, fresh, self._view(game), self._secret if valid else None
            )

    def _refresh(self, game: _Game) -> None:
        game.public_key, game.private_key = generate_keypair(self.parameters)
        game.nonce = secrets.randbelow(self.parameters.q)
        game.oracle_messages.clear()
        game.queries = 0
        game.complete = False

    def _game(self, game_id: str) -> _Game:
        try:
            return self._games[game_id]
        except KeyError as error:
            raise GameError("game was not found", 404) from error

    @staticmethod
    def _validate_message(message: bytes) -> None:
        if len(message) > MAX_MESSAGE_BYTES:
            raise GameError(f"message must not exceed {MAX_MESSAGE_BYTES} bytes")

    @staticmethod
    def _require_incomplete(game: _Game) -> None:
        if game.complete:
            raise GameError("this game is complete; reset it to play again", 409)

    def _view(self, game: _Game) -> GameView:
        return GameView(
            game.game_id,
            self.parameters,
            game.public_key.value,
            game.queries,
            int(game.complete),
            game.complete,
        )
