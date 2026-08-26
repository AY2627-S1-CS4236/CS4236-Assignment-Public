"""Restricted chosen-plaintext game state and cipher-suite adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
import importlib
import secrets
import threading
from typing import Protocol


BLOCK_BYTES = 16
KEY_BYTES = 16
IV_BYTES = BLOCK_BYTES
ROUNDS = 10
WINS_REQUIRED = 30
MAX_MESSAGE_BYTES = 4096
SUITE_NAME = "spn-cbc-v1"

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
    """A client supplied an invalid R-CPA game operation."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class CipherOutput:
    initialization_vector: bytes
    ciphertext: bytes


class CipherInstance(Protocol):
    """One suite instance with fresh secret cryptographic state."""

    suite_name: str
    ciphertext_group_bytes: int | None

    def encrypt(self, plaintext: bytes) -> CipherOutput:
        """Return the initialization vector and ciphertext separately."""


class CipherSuiteFactory(Protocol):
    """Create independent cipher instances for new or reset games."""

    def create(self) -> CipherInstance:
        """Return a cipher instance with fresh secret state."""


class SpnCbcCipher:
    """One SPN-CBC game instance with a fixed key and IV."""

    suite_name = SUITE_NAME
    ciphertext_group_bytes = BLOCK_BYTES

    def __init__(self, key: bytes | None = None, iv: bytes | None = None) -> None:
        self._key = secrets.token_bytes(KEY_BYTES) if key is None else key
        self.iv = secrets.token_bytes(IV_BYTES) if iv is None else iv
        if len(self._key) != KEY_BYTES:
            raise ValueError("CBC key must contain exactly 16 bytes")
        if len(self.iv) != IV_BYTES:
            raise ValueError("CBC IV must contain exactly 16 bytes")

        modes = importlib.import_module("educrypto.modes")
        self._encrypt_cbc = modes.encrypt_cbc

    def encrypt(self, plaintext: bytes) -> CipherOutput:
        ciphertext = self._encrypt_cbc(
            self._key,
            plaintext,
            iv=self.iv,
            sbox=SBOX,
            rounds=ROUNDS,
        )
        return CipherOutput(
            initialization_vector=self.iv,
            ciphertext=ciphertext,
        )


class SpnCbcSuiteFactory:
    """Create SPN-CBC instances with a fresh random key and IV."""

    def create(self) -> SpnCbcCipher:
        return SpnCbcCipher()


@dataclass(frozen=True, slots=True)
class SuiteView:
    name: str
    ciphertext_group_bytes: int | None


@dataclass(frozen=True, slots=True)
class GameView:
    game_id: str
    suite: SuiteView
    wins: int
    wins_required: int


@dataclass(frozen=True, slots=True)
class EncryptionView:
    initialization_vector: bytes
    ciphertext: bytes


@dataclass(frozen=True, slots=True)
class GuessResult:
    correct: bool
    wins: int
    wins_required: int
    secret: str | None


@dataclass(slots=True)
class _ActiveChallenge:
    choice: int


@dataclass(slots=True)
class _Game:
    game_id: str
    cipher: CipherInstance
    wins: int = 0
    oracle_messages: set[bytes] = field(default_factory=set)
    challenge_messages: set[bytes] = field(default_factory=set)
    active: _ActiveChallenge | None = None
    complete: bool = False


class RcpaGameService:
    """Track independent R-CPA sessions and their consecutive-win streaks."""

    def __init__(
        self,
        secret: str,
        suite_factory: CipherSuiteFactory | None = None,
    ) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("the startup secret must not be empty")

        self._secret = secret
        self._suite_factory = suite_factory or SpnCbcSuiteFactory()
        self._games: dict[str, _Game] = {}
        self._lock = threading.Lock()

    def create_game(self) -> GameView:
        with self._lock:
            game_id = f"game_{secrets.token_hex(16)}"
            game = _Game(game_id=game_id, cipher=self._suite_factory.create())
            self._games[game_id] = game
            return self._view(game)

    def reset_game(self, game_id: str) -> GameView:
        with self._lock:
            game = self._game(game_id)
            self._start_new_game(game)
            return self._view(game)

    def encrypt_with_oracle(
        self,
        game_id: str,
        plaintext: bytes,
    ) -> EncryptionView:
        self._validate_plaintext(plaintext)

        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            if plaintext in game.challenge_messages:
                raise GameError(
                    "a challenge message cannot be submitted to the oracle",
                    409,
                )

            output = game.cipher.encrypt(plaintext)
            game.oracle_messages.add(plaintext)
            return EncryptionView(
                initialization_vector=output.initialization_vector,
                ciphertext=output.ciphertext,
            )

    def create_challenge(
        self,
        game_id: str,
        left: bytes,
        right: bytes,
    ) -> EncryptionView:
        self._validate_messages(left, right)

        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            if game.active is not None:
                raise GameError("guess the active challenge before starting another", 409)
            if left in game.oracle_messages or right in game.oracle_messages:
                raise GameError(
                    "an oracle message cannot be used as a challenge candidate",
                    409,
                )

            choice = secrets.randbelow(2)
            output = game.cipher.encrypt(left if choice == 0 else right)
            game.challenge_messages.update((left, right))
            game.active = _ActiveChallenge(choice=choice)
            return EncryptionView(
                initialization_vector=output.initialization_vector,
                ciphertext=output.ciphertext,
            )

    def guess(self, game_id: str, guess: int) -> GuessResult:
        if type(guess) is not int or guess not in (0, 1):
            raise GameError("guess must be either 0 or 1")

        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            if game.active is None:
                raise GameError("this game has no active challenge", 409)

            correct = guess == game.active.choice
            game.active = None
            if correct:
                game.wins = min(game.wins + 1, WINS_REQUIRED)
            else:
                game.wins = 0

            secret = None
            if game.wins == WINS_REQUIRED:
                game.complete = True
                secret = self._secret
            else:
                # One guess ends one R-CPA game. Start the next game with fresh
                # cryptographic state while carrying the updated streak forward.
                self._start_new_game(game)

            return GuessResult(
                correct=correct,
                wins=game.wins,
                wins_required=WINS_REQUIRED,
                secret=secret,
            )

    def _start_new_game(self, game: _Game) -> None:
        game.cipher = self._suite_factory.create()
        game.oracle_messages.clear()
        game.challenge_messages.clear()
        game.active = None
        game.complete = False

    @staticmethod
    def _validate_messages(left: bytes, right: bytes) -> None:
        RcpaGameService._validate_plaintext(left)
        RcpaGameService._validate_plaintext(right)
        if len(left) != len(right):
            raise GameError("challenge candidates must have equal lengths")
        if left == right:
            raise GameError("challenge candidates must be distinct")

    @staticmethod
    def _validate_plaintext(plaintext: bytes) -> None:
        if not plaintext:
            raise GameError("plaintext must be non-empty")
        if len(plaintext) > MAX_MESSAGE_BYTES:
            raise GameError(
                f"plaintext must not exceed {MAX_MESSAGE_BYTES} bytes"
            )

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
                name=game.cipher.suite_name,
                ciphertext_group_bytes=game.cipher.ciphertext_group_bytes,
            ),
            wins=game.wins,
            wins_required=WINS_REQUIRED,
        )
