"""Win the Week 03 restricted chosen-plaintext game."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen


def _post_json(
    base_url: str,
    path: str,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    data = b"" if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def solve(base_url: str) -> str:
    """Win 30 consecutive R-CPA rounds and return the startup secret."""

    game = _post_json(base_url, "/api/v1/games")
    game_id = game.get("game_id")
    suite = game.get("suite")
    block_bytes = suite.get("ciphertext_group_bytes")
    # The complete oracle message differs from both candidates. Its first
    # block matches only the left candidate, which is enough to make the first
    # CBC ciphertext block a reliable distinguisher under the reused IV.
    shared_first_block = b"Q" * block_bytes
    oracle_message = shared_first_block + (b"O" * block_bytes)
    left = shared_first_block + (b"L" * block_bytes)
    right = (b"R" * block_bytes) + (b"1" * block_bytes)

    wins_required = game.get("wins_required")

    for _round in range(wins_required):
        # Each guess starts a new game with a fresh key and IV, so establish a
        # new reference ciphertext inside every game.
        oracle = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/oracle",
            {"message_hex": oracle_message.hex()},
        )
        oracle_ciphertext = bytes.fromhex(oracle.get("ciphertext_hex"))
        reference_block = oracle_ciphertext[:block_bytes]

        challenge = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/challenge",
            {"left_hex": left.hex(), "right_hex": right.hex()},
        )
        challenge_ciphertext = bytes.fromhex(challenge.get("ciphertext_hex"))
        guess = 0 if challenge_ciphertext[:block_bytes] == reference_block else 1
        result = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/guess",
            {"guess": guess},
        )
        secret = result.get("secret")
        if isinstance(secret, str):
            return secret

    raise ValueError("the R-CPA game ended without returning the secret")
