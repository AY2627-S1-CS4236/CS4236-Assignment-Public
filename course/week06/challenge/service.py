"""IND-CCA2 game using CTR, CMAC, and a public iterated hash."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import secrets
import threading


BLOCK_BYTES = 16
IV_BYTES = 8
MAX_AD_BYTES = 15
TAG_BYTES = 16
KEY_BYTES = 48
ROUNDS = 10
MULTIPLIER = 7
MODULUS = 1 << 128
WINS_REQUIRED = 30
MAX_MESSAGE_BYTES = 4096
MAX_CIPHERTEXT_BYTES = MAX_MESSAGE_BYTES + 2 * BLOCK_BYTES
SUITE_NAME = "spn-ctr-chain-hash-cmac-v1"

# AES S-box used throughout the course.
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


def _pad_associated_data(associated_data: bytes) -> bytes:
    return associated_data + b"\x80" + bytes(15 - len(associated_data))


def challenge_hash(ciphertext: bytes) -> bytes:
    """Chain 128-bit ciphertext blocks with H <- 7H + B modulo 2^128."""

    state = 0
    for offset in range(0, len(ciphertext), BLOCK_BYTES):
        block = ciphertext[offset : offset + BLOCK_BYTES].ljust(
            BLOCK_BYTES,
            b"\x00",
        )
        state = (MULTIPLIER * state + int.from_bytes(block, "big")) % MODULUS
    return state.to_bytes(BLOCK_BYTES, "big")


class GameError(ValueError):
    """A client supplied an invalid CCA game operation."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class AeadOutput:
    iv: bytes
    associated_data: bytes
    ciphertext: bytes
    tag: bytes


class EtmCipher:
    """One keyed instance of the challenge ETM construction."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = secrets.token_bytes(KEY_BYTES) if key is None else key
        self._encryption_key = self._key[:BLOCK_BYTES]
        self._mac_key = self._key[BLOCK_BYTES:]
        modes = importlib.import_module("educrypto.modes")
        mac = importlib.import_module("educrypto.mac")
        self._encrypt_ctr = modes.encrypt_ctr
        self._decrypt_ctr = modes.decrypt_ctr
        self._cmac = mac.cmac
        self._verify_cmac = mac.verify_cmac

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes,
        *,
        iv: bytes | None = None,
    ) -> AeadOutput:
        nonce = secrets.token_bytes(IV_BYTES) if iv is None else iv
        ciphertext = self._encrypt_ctr(
            self._encryption_key,
            plaintext,
            iv=nonce,
            sbox=SBOX,
            rounds=ROUNDS,
        )
        digest = challenge_hash(ciphertext)
        tag = self._cmac(
            self._mac_key,
            nonce + _pad_associated_data(associated_data) + digest,
            sbox=SBOX,
            rounds=ROUNDS,
        )
        return AeadOutput(nonce, associated_data, ciphertext, tag)

    def decrypt(
        self,
        iv: bytes,
        associated_data: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> bytes | None:
        digest = challenge_hash(ciphertext)
        if not self._verify_cmac(
            self._mac_key,
            iv + _pad_associated_data(associated_data) + digest,
            tag,
            sbox=SBOX,
            rounds=ROUNDS,
        ):
            return None
        return self._decrypt_ctr(
            self._encryption_key,
            ciphertext,
            iv=iv,
            sbox=SBOX,
            rounds=ROUNDS,
        )


@dataclass(frozen=True, slots=True)
class GameView:
    game_id: str
    wins: int
    complete: bool


@dataclass(frozen=True, slots=True)
class DecryptionResult:
    valid: bool
    plaintext: bytes | None


@dataclass(frozen=True, slots=True)
class GuessResult:
    correct: bool
    wins: int
    secret: str | None


@dataclass(slots=True)
class _ActiveChallenge:
    choice: int
    output: AeadOutput


@dataclass(slots=True)
class _Game:
    game_id: str
    cipher: EtmCipher
    wins: int = 0
    active: _ActiveChallenge | None = None
    complete: bool = False


class CcaGameService:
    """Track independent games and consecutive IND-CCA2 wins."""

    def __init__(self, secret: str) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("the startup secret must not be empty")
        self._secret = secret
        self._games: dict[str, _Game] = {}
        self._lock = threading.Lock()

    def create_game(self) -> GameView:
        with self._lock:
            game_id = f"game_{secrets.token_hex(16)}"
            game = _Game(game_id, EtmCipher())
            self._games[game_id] = game
            return self._view(game)

    def reset_game(self, game_id: str) -> GameView:
        with self._lock:
            game = self._game(game_id)
            self._refresh_instance(game)
            return self._view(game)

    def encrypt_with_oracle(
        self,
        game_id: str,
        plaintext: bytes,
        associated_data: bytes,
    ) -> AeadOutput:
        self._validate_message(plaintext)
        self._validate_associated_data(associated_data)
        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            return game.cipher.encrypt(plaintext, associated_data)

    def create_challenge(
        self,
        game_id: str,
        left: bytes,
        right: bytes,
        associated_data: bytes,
    ) -> AeadOutput:
        self._validate_candidates(left, right)
        self._validate_associated_data(associated_data)
        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            if game.active is not None:
                raise GameError("guess the active challenge before starting another", 409)
            choice = secrets.randbelow(2)
            output = game.cipher.encrypt(
                left if choice == 0 else right,
                associated_data,
            )
            game.active = _ActiveChallenge(choice, output)
            return output

    def decrypt_with_oracle(
        self,
        game_id: str,
        iv: bytes,
        associated_data: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> DecryptionResult:
        self._validate_iv(iv)
        self._validate_associated_data(associated_data)
        self._validate_ciphertext(ciphertext)
        self._validate_tag(tag)
        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            if game.active is not None:
                submitted = AeadOutput(iv, associated_data, ciphertext, tag)
                if submitted == game.active.output:
                    raise GameError(
                        "the exact active challenge cannot be sent to the decryption oracle",
                        409,
                    )
            plaintext = game.cipher.decrypt(iv, associated_data, ciphertext, tag)
            return DecryptionResult(plaintext is not None, plaintext)

    def guess(self, game_id: str, guess: object) -> GuessResult:
        if type(guess) is not int or guess not in (0, 1):
            raise GameError("guess must be either 0 or 1")
        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            if game.active is None:
                raise GameError("this game has no active challenge", 409)
            correct = guess == game.active.choice
            game.wins = min(game.wins + 1, WINS_REQUIRED) if correct else 0
            secret = None
            if game.wins == WINS_REQUIRED:
                game.complete = True
                game.active = None
                secret = self._secret
            else:
                self._refresh_instance(game)
            return GuessResult(correct, game.wins, secret)

    @staticmethod
    def _validate_message(message: bytes) -> None:
        if len(message) > MAX_MESSAGE_BYTES:
            raise GameError(f"message must not exceed {MAX_MESSAGE_BYTES} bytes")

    @staticmethod
    def _validate_candidates(left: bytes, right: bytes) -> None:
        CcaGameService._validate_message(left)
        CcaGameService._validate_message(right)
        if len(left) != len(right):
            raise GameError("challenge candidates must have equal lengths")
        if left == right:
            raise GameError("challenge candidates must be distinct")

    @staticmethod
    def _validate_iv(iv: bytes) -> None:
        if len(iv) != IV_BYTES:
            raise GameError(f"iv must contain exactly {IV_BYTES} bytes")

    @staticmethod
    def _validate_associated_data(associated_data: bytes) -> None:
        if len(associated_data) > MAX_AD_BYTES:
            raise GameError(
                f"associated_data must not exceed {MAX_AD_BYTES} bytes"
            )

    @staticmethod
    def _validate_ciphertext(ciphertext: bytes) -> None:
        if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
            raise GameError(
                f"ciphertext must not exceed {MAX_CIPHERTEXT_BYTES} bytes"
            )

    @staticmethod
    def _validate_tag(tag: bytes) -> None:
        if len(tag) != TAG_BYTES:
            raise GameError(f"tag must contain exactly {TAG_BYTES} bytes")

    @staticmethod
    def _refresh_instance(game: _Game) -> None:
        game.cipher = EtmCipher()
        game.active = None
        game.complete = False

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
        return GameView(game.game_id, game.wins, game.complete)
