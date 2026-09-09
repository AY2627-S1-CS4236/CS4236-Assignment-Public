"""Two-target collision game built from the student's Week 05 sponge."""

from __future__ import annotations

from dataclasses import dataclass, field
from hmac import compare_digest
import importlib
import secrets
import threading


STATE_BYTES = 16
ROUNDS = 10
WINS_REQUIRED = 2
MAX_MESSAGE_BYTES = 4096
SUITE_NAME = "fixed-key-spn-sponge-v2"


@dataclass(frozen=True, slots=True)
class HashTarget:
    hash_id: str
    capacity_bytes: int
    digest_bytes: int

    @property
    def rate_bytes(self) -> int:
        return STATE_BYTES - self.capacity_bytes


TARGETS = (
    HashTarget("hash1", capacity_bytes=13, digest_bytes=3),
    HashTarget("hash2", capacity_bytes=3, digest_bytes=32),
)
TARGETS_BY_ID = {target.hash_id: target for target in TARGETS}


class ChallengeHasher:
    """Apply the fixed challenge hash parameters to one message."""

    def __init__(self) -> None:
        hashing = importlib.import_module("educrypto.hashing")
        self._sponge_hash = hashing.sponge_hash
        self._sbox = hashing.AES_SBOX

    def digest(self, target: HashTarget, message: bytes) -> bytes:
        """Hash a message for one target without reading or changing game state."""

        return self._sponge_hash(
            message,
            c=target.capacity_bytes,
            digest_length=target.digest_bytes,
            sbox=self._sbox,
            rounds=ROUNDS,
        )


class GameError(ValueError):
    """A client supplied an invalid collision game operation."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class GameView:
    game_id: str
    solved: frozenset[str]


@dataclass(frozen=True, slots=True)
class CollisionResult:
    hash_id: str
    valid: bool
    distinct: bool
    left_digest: bytes
    right_digest: bytes
    wins: int
    secret: str | None


@dataclass(slots=True)
class _Game:
    game_id: str
    solved: set[str] = field(default_factory=set)


class CollisionGameService:
    """Track independent games and reveal the secret after both collisions."""

    def __init__(
        self,
        secret: str,
    ) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("the startup secret must not be empty")
        self._secret = secret
        self._games: dict[str, _Game] = {}
        self._lock = threading.Lock()
        self._hasher = ChallengeHasher()

    def create_game(self) -> GameView:
        with self._lock:
            game_id = f"game_{secrets.token_hex(16)}"
            game = _Game(game_id=game_id)
            self._games[game_id] = game
            return self._view(game)

    def reset_game(self, game_id: str) -> GameView:
        with self._lock:
            game = self._game(game_id)
            game.solved.clear()
            return self._view(game)

    def hash_message(self, game_id: str, hash_id: object, message: bytes) -> bytes:
        self._validate_message(message)
        with self._lock:
            game = self._game(game_id)
            target = self._target(hash_id)
            self._require_unsolved(game, target)
            return self._hasher.digest(target, message)

    def submit_collision(
        self,
        game_id: str,
        hash_id: object,
        left: bytes,
        right: bytes,
    ) -> CollisionResult:
        self._validate_message(left)
        self._validate_message(right)
        with self._lock:
            game = self._game(game_id)
            target = self._target(hash_id)
            self._require_unsolved(game, target)
            left_digest = self._hasher.digest(target, left)
            right_digest = self._hasher.digest(target, right)
            distinct = left != right
            valid = distinct and compare_digest(left_digest, right_digest)

            revealed_secret = None
            if valid:
                game.solved.add(target.hash_id)
                if len(game.solved) == WINS_REQUIRED:
                    revealed_secret = self._secret

            return CollisionResult(
                hash_id=target.hash_id,
                valid=valid,
                distinct=distinct,
                left_digest=left_digest,
                right_digest=right_digest,
                wins=len(game.solved),
                secret=revealed_secret,
            )

    @staticmethod
    def _validate_message(message: bytes) -> None:
        if len(message) > MAX_MESSAGE_BYTES:
            raise GameError(f"message must not exceed {MAX_MESSAGE_BYTES} bytes")

    @staticmethod
    def _target(hash_id: object) -> HashTarget:
        if not isinstance(hash_id, str):
            raise GameError("hash_id must be a string")
        try:
            return TARGETS_BY_ID[hash_id]
        except KeyError as error:
            raise GameError("hash_id must be 'hash1' or 'hash2'") from error

    @staticmethod
    def _require_unsolved(game: _Game, target: HashTarget) -> None:
        if target.hash_id in game.solved:
            raise GameError("this hash target is already solved; reset to replay it", 409)

    def _game(self, game_id: str) -> _Game:
        try:
            return self._games[game_id]
        except KeyError as error:
            raise GameError("game was not found", 404) from error

    @staticmethod
    def _view(game: _Game) -> GameView:
        return GameView(game_id=game.game_id, solved=frozenset(game.solved))
