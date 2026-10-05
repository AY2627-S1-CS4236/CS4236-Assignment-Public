"""Reference solution for the Week 06 ETM CCA game."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

BLOCK_BYTES = 16
MODULUS = 1 << (8 * BLOCK_BYTES)


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


def _extend_ciphertext(ciphertext: bytes) -> bytes:
    """Append -6 times the final ciphertext block modulo 2^128."""

    last_block = int.from_bytes(ciphertext[-BLOCK_BYTES:], "big")
    extension = (-6 * last_block % MODULUS).to_bytes(BLOCK_BYTES, "big")
    return ciphertext + extension


def solve(base_url: str) -> str:
    """Win 30 consecutive CCA rounds and return the revealed server secret."""

    game = _post_json(base_url, "/api/v1/games")
    game_id = game["game_id"]
    wins_required = game["wins_required"]
    associated_data = b"C" * 15
    left = b"A" * 16
    right = b"B" * 16

    for _round in range(wins_required):
        challenge = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/challenge",
            {
                "left_hex": left.hex(),
                "right_hex": right.hex(),
                "associated_data_hex": associated_data.hex(),
            },
        )
        iv = bytes.fromhex(challenge["iv_hex"])
        ad = bytes.fromhex(challenge["associated_data_hex"])
        ciphertext = bytes.fromhex(challenge["ciphertext_hex"])
        tag = bytes.fromhex(challenge["tag_hex"])
        forged_ciphertext = _extend_ciphertext(ciphertext)

        decrypted = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/oracle/decrypt",
            {
                "iv_hex": iv.hex(),
                "associated_data_hex": ad.hex(),
                "ciphertext_hex": forged_ciphertext.hex(),
                "tag_hex": tag.hex(),
            },
        )
        plaintext = bytes.fromhex(decrypted["plaintext_hex"])
        guess = 0 if plaintext[:BLOCK_BYTES] == left else 1

        result = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/guess",
            {"guess": guess},
        )
        secret = result.get("secret")
        if isinstance(secret, str):
            return secret

    return result["secret"]
