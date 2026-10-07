"""ElGamal chosen-plaintext game over a deliberately small subgroup."""

from __future__ import annotations

from dataclasses import dataclass
import secrets
import threading

from educrypto.dh import (
    DHParameters,
    DHPrivateKey,
    DHPublicKey,
    derive_shared_key,
    generate_keypair,
)
from educrypto.primality import is_probable_prime


WINS_REQUIRED = 30
SMALL_PRIME_MIN = 1 << 14
SMALL_PRIME_MAX = 1 << 15
LARGE_PRIME_BITS = 256
SUITE_NAME = "elgamal-small-subgroup-v1"


def generate_weak_parameters() -> DHParameters:
    while True:
        q_small = SMALL_PRIME_MIN + secrets.randbelow(
            SMALL_PRIME_MAX - SMALL_PRIME_MIN
        )
        if not is_probable_prime(q_small):
            continue
        while True:
            q_large = (1 << (LARGE_PRIME_BITS - 1)) | secrets.randbits(
                LARGE_PRIME_BITS - 1
            ) | 1
            if not is_probable_prime(q_large):
                continue
            p = 2 * q_small * q_large + 1
            if not is_probable_prime(p) or pow(2, q_small, p) == 1:
                continue
            while True:
                h = secrets.randbelow(p - 3) + 2
                g = pow(h, (p - 1) // q_small, p)
                if g != 1:
                    return DHParameters(int(p), int(g), int(q_small))


class GameError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class Ciphertext:
    c1: int
    c2: int


class ElGamalCipher:
    def __init__(self, parameters: DHParameters) -> None:
        self.parameters = parameters
        x = secrets.randbelow(parameters.p - 1) + 1
        self._private_key = DHPrivateKey(parameters, x)
        self.public_key = DHPublicKey(parameters, pow(parameters.g, x, parameters.p))

    def encrypt(self, message: int) -> Ciphertext:
        ephemeral_public, ephemeral_private = generate_keypair(
            parameters=self.parameters
        )
        shared = derive_shared_key(ephemeral_private, self.public_key)
        return Ciphertext(
            ephemeral_public.value,
            (message * shared) % self.parameters.p,
        )

    def decrypt(self, output: Ciphertext) -> int:
        """Internal reference operation; the CPA game exposes no decrypt route."""

        ephemeral_public = DHPublicKey(self.parameters, output.c1)
        shared = derive_shared_key(self._private_key, ephemeral_public)
        return (output.c2 * pow(shared, -1, self.parameters.p)) % self.parameters.p


@dataclass(frozen=True, slots=True)
class GameView:
    game_id: str
    p: int
    g: int
    public_key: int
    wins: int
    complete: bool


@dataclass(frozen=True, slots=True)
class GuessResult:
    correct: bool
    wins: int
    public_key: int | None
    secret: str | None


@dataclass(slots=True)
class _ActiveChallenge:
    choice: int
    ciphertext: Ciphertext


@dataclass(slots=True)
class _Game:
    game_id: str
    cipher: ElGamalCipher
    wins: int = 0
    active: _ActiveChallenge | None = None
    complete: bool = False


class ElGamalGameService:
    """Manage independent game IDs and consecutive correct guesses."""

    def __init__(self, secret: str, parameters: DHParameters | None = None) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("the startup secret must not be empty")
        self._secret = secret
        self.parameters = (
            generate_weak_parameters() if parameters is None else parameters
        )
        if pow(2, self.parameters.q, self.parameters.p) == 1:
            raise ValueError("2 must lie outside the challenge subgroup")
        self._games: dict[str, _Game] = {}
        self._lock = threading.Lock()

    def create_game(self) -> GameView:
        with self._lock:
            game_id = f"game_{secrets.token_hex(16)}"
            game = _Game(game_id, ElGamalCipher(self.parameters))
            self._games[game_id] = game
            return self._view(game)

    def reset_game(self, game_id: str) -> GameView:
        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            self._refresh(game)
            return self._view(game)

    def create_challenge(self, game_id: str, left: int, right: int) -> Ciphertext:
        self._validate_message(left)
        self._validate_message(right)
        if left == right:
            raise GameError("challenge candidates must be distinct")
        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            if game.active is not None:
                raise GameError("guess the active challenge first", 409)
            choice = secrets.randbelow(2)
            ciphertext = game.cipher.encrypt(left if choice == 0 else right)
            game.active = _ActiveChallenge(choice, ciphertext)
            return ciphertext

    def guess(self, game_id: str, guess: object) -> GuessResult:
        if type(guess) is not int or guess not in (0, 1):
            raise GameError("guess must be 0 or 1")
        with self._lock:
            game = self._game(game_id)
            self._require_incomplete(game)
            if game.active is None:
                raise GameError("this game has no active challenge", 409)
            correct = guess == game.active.choice
            game.wins = game.wins + 1 if correct else 0
            if game.wins == WINS_REQUIRED:
                game.complete = True
                game.active = None
                return GuessResult(correct, game.wins, None, self._secret)
            self._refresh(game)
            return GuessResult(correct, game.wins, game.cipher.public_key.value, None)

    def _validate_message(self, message: int) -> None:
        if type(message) is not int or not 1 <= message < self.parameters.p:
            raise GameError("message must be an integer from 1 through p - 1")

    def _game(self, game_id: str) -> _Game:
        try:
            return self._games[game_id]
        except KeyError as error:
            raise GameError("game was not found", 404) from error

    @staticmethod
    def _require_incomplete(game: _Game) -> None:
        if game.complete:
            raise GameError("this game is complete", 409)

    def _refresh(self, game: _Game) -> None:
        previous_public_key = game.cipher.public_key.value
        while True:
            replacement = ElGamalCipher(self.parameters)
            if replacement.public_key.value != previous_public_key:
                game.cipher = replacement
                break
        game.active = None

    def _view(self, game: _Game) -> GameView:
        return GameView(
            game.game_id,
            self.parameters.p,
            self.parameters.g,
            game.cipher.public_key.value,
            game.wins,
            game.complete,
        )
