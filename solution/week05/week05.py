"""Break both Week 05 sponge targets and recover the server secret."""

from __future__ import annotations

import json
from functools import cache
from itertools import count
from urllib.request import Request, urlopen

from ..hashing import AES_SBOX, SPONGE_KEY, sponge_hash
from ..spn import encrypt_block


BLOCK_SIZE = 16
ROUNDS = 10


def _post_json(
    base_url: str,
    path: str,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    data = b"" if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=5) as response:
        return json.load(response)


@cache
def _short_digest_collision() -> tuple[bytes, bytes]:
    """Birthday-search the 24-bit digest in about 2^(24/2) messages."""

    seen: dict[bytes, bytes] = {}
    for value in count():
        message = value.to_bytes(3, "big")
        digest = sponge_hash(message, c=13, digest_length=3, rounds=ROUNDS)
        previous = seen.get(digest)
        if previous is not None:
            return previous, message
        seen[digest] = message


@cache
def _small_capacity_collision() -> tuple[bytes, bytes]:
    """Build p1 || t1 and p2 || t2 after a capacity collision."""

    rate = 13
    capacity_bytes = BLOCK_SIZE - rate
    seen: dict[bytes, tuple[bytes, bytes]] = {}
    for value in count():
        first_block = value.to_bytes(rate, "big")
        state = encrypt_block(
            SPONGE_KEY,
            first_block + bytes(capacity_bytes),
            sbox=AES_SBOX,
            rounds=ROUNDS,
        )
        capacity = state[rate:]
        previous = seen.get(capacity)
        if previous is not None:
            previous_block, previous_state = previous
            # Write S1 = t1 || C and S2 = t2 || C. The second blocks t1 and
            # t2 cancel their respective rate portions, so both next
            # permutation inputs are exactly 0^13 || C.
            left = previous_block + previous_state[:rate]
            right = first_block + state[:rate]
            # These distinct 26-byte messages receive identical pad10*1.
            # The merged states remain equal through padding and squeezing,
            # regardless of how many output bytes the caller requests.
            return left, right
        seen[capacity] = first_block, state


def solve(base_url: str) -> str:
    """Solve each target once and return the secret revealed after both wins."""

    game = _post_json(base_url, "/api/v1/games")
    game_id = game["game_id"]
    secret = None
    for hash_id, find_collision in (
        ("hash1", _short_digest_collision),
        ("hash2", _small_capacity_collision),
    ):
        left, right = find_collision()
        result = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/collide",
            {"hash_id": hash_id, "left_hex": left.hex(), "right_hex": right.hex()},
        )
        if result.get("valid") is not True:
            raise ValueError(f"the collision for {hash_id} was rejected")
        if result.get("complete") is True:
            secret = result.get("secret")
    if not isinstance(secret, str):
        raise ValueError("the server did not reveal the secret after both wins")
    return secret
