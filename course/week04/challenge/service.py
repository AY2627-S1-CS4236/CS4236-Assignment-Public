"""EUF-CMA game state and the deliberately flawed PFMAC adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from hmac import compare_digest
import importlib
import secrets
import threading
from typing import Protocol


BLOCK_BYTES = 16
KEY_BYTES = BLOCK_BYTES
TAG_BYTES = 2 * BLOCK_BYTES
ROUNDS = 10
WINS_REQUIRED = 1
MAX_MESSAGE_BYTES = 4096
SUITE_NAME = "spn-pfmac-two-block-v1"
ZERO_IV = bytes(BLOCK_BYTES)

# AES S-box, reused as the fixed challenge configuration.
SBOX = bytes.fromhex(
    """
    63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
    ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
    b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
    04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
    09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
    53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
    d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
    51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
    cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
    60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
    e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
    e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
    ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
    70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
    e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
    8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
    """
)


class GameError(ValueError):
    """A client supplied an invalid EUF-CMA game operation."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class TagInstance(Protocol):
    """One tag scheme instance with fresh secret cryptographic state."""

    suite_name: str
    tag_group_bytes: int | None
    tag_bytes: int

    def tag(self, message: bytes) -> bytes:
        """Return an authentication tag for ``message``."""

    def verify(self, message: bytes, tag: bytes) -> bool:
        """Return whether ``tag`` authenticates ``message``."""


class TagSuiteFactory(Protocol):
    """Create independent tag instances for new or reset rounds."""

    def create(self) -> TagInstance:
        """Return a tag instance with fresh secret state."""


class SpnPfmacTwoBlock:
    """PFMAC misuse that exposes the final two CBC chaining values."""

    suite_name = SUITE_NAME
    tag_group_bytes = BLOCK_BYTES
    tag_bytes = TAG_BYTES

    def __init__(self, key: bytes | None = None) -> None:
        self._key = secrets.token_bytes(KEY_BYTES) if key is None else key
        if len(self._key) != KEY_BYTES:
            raise ValueError("PFMAC key must contain exactly 16 bytes")

        modes = importlib.import_module("educrypto.modes")
        self._encrypt_cbc = modes.encrypt_cbc
        self._pkcs7_pad = modes.pkcs7_pad

    def tag(self, message: bytes) -> bytes:
        padded_block_count = len(self._pkcs7_pad(message)) // BLOCK_BYTES
        encoded_count = padded_block_count.to_bytes(BLOCK_BYTES, byteorder="big")
        ciphertext = self._encrypt_cbc(
            self._key,
            encoded_count + message,
            iv=ZERO_IV,
            sbox=SBOX,
            rounds=ROUNDS,
        )
        return ciphertext[-TAG_BYTES:]

    def verify(self, message: bytes, tag: bytes) -> bool:
        return len(tag) == TAG_BYTES and compare_digest(self.tag(message), tag)


class SpnPfmacTwoBlockFactory:
    """Create flawed-PFMAC instances with fresh random keys."""

    def create(self) -> SpnPfmacTwoBlock:
        return SpnPfmacTwoBlock()


@dataclass(frozen=True, slots=True)
class SuiteView:
    name: str
    tag_group_bytes: int | None
    tag_bytes: int


@dataclass(frozen=True, slots=True)
class GameView:
    game_id: str
    suite: SuiteView
    wins: int
    wins_required: int


@dataclass(frozen=True, slots=True)
class ForgeryResult:
    valid: bool
    fresh: bool
    wins: int
    wins_required: int
    secret: str | None


@dataclass(slots=True)
class _Game:
    game_id: str
    tagger: TagInstance
    wins: int = 0
    oracle_messages: set[bytes] = field(default_factory=set)
    complete: bool = False


class EufCmaGameService:
    """Track independent EUF-CMA sessions and their forgery objective."""

    def __init__(
        self,
        secret: str,
        suite_factory: TagSuiteFactory | None = None,
    ) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("the startup secret must not be empty")

        self._secret = secret
        self._suite_factory = suite_factory or SpnPfmacTwoBlockFactory()
        self._games: dict[str, _Game] = {}
        self._lock = threading.Lock()

    def create_game(self) -> GameView:
        with self._lock:
            game_id = f"game_{secrets.token_hex(16)}"
            game = _Game(game_id=game_id, tagger=self._suite_factory.create())
            self._games[game_id] = game
            return self._view(game)

    def reset_game(self, game_id: str) -> GameView:
        with self._lock:
            game = self._game(game_id)
            game.wins = 0
            self._start_new_round(game)
            return self._view(game)

    def tag_with_oracle(self, game_id: str, message: bytes) -> bytes:
        self._validate_message(message)

        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            tag = game.tagger.tag(message)
            game.oracle_messages.add(message)
            return tag

    def submit_forgery(
        self,
        game_id: str,
        message: bytes,
        tag: bytes,
    ) -> ForgeryResult:
        self._validate_message(message)
        if len(tag) != TAG_BYTES:
            raise GameError(f"tag must contain exactly {TAG_BYTES} bytes")

        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            fresh = message not in game.oracle_messages
            valid = fresh and game.tagger.verify(message, tag)

            if valid:
                game.wins = min(game.wins + 1, WINS_REQUIRED)
            else:
                game.wins = 0

            secret = None
            if game.wins == WINS_REQUIRED:
                game.complete = True
                secret = self._secret
            else:
                self._start_new_round(game)

            return ForgeryResult(
                valid=valid,
                fresh=fresh,
                wins=game.wins,
                wins_required=WINS_REQUIRED,
                secret=secret,
            )

    def _start_new_round(self, game: _Game) -> None:
        game.tagger = self._suite_factory.create()
        game.oracle_messages.clear()
        game.complete = False

    @staticmethod
    def _validate_message(message: bytes) -> None:
        if len(message) > MAX_MESSAGE_BYTES:
            raise GameError(f"message must not exceed {MAX_MESSAGE_BYTES} bytes")

    @staticmethod
    def _require_incomplete(game: _Game) -> None:
        if game.complete:
            raise GameError("this game is complete; reset it to play again", 409)

    def _game(self, game_id: str) -> _Game:
        try:
            return self._games[game_id]
        except KeyError as error:
            raise GameError("game was not found", 404) from error

    @staticmethod
    def _view(game: _Game) -> GameView:
        return GameView(
            game_id=game.game_id,
            suite=SuiteView(
                name=game.tagger.suite_name,
                tag_group_bytes=game.tagger.tag_group_bytes,
                tag_bytes=game.tagger.tag_bytes,
            ),
            wins=game.wins,
            wins_required=WINS_REQUIRED,
        )
