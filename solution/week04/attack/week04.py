"""Win the Week 04 EUF-CMA forgery game."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen


BLOCK_SIZE = 16
MAX_QUERIES = 257
COMMON_SUFFIX = b"A" * (BLOCK_SIZE - 1)


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
    """Produce one fresh-message forgery and return the startup secret."""

    game = _post_json(base_url, "/api/v1/games")
    game_id = game.get("game_id")

    # Query messages B_i || ("A" * 15). Padding turns their final block into
    # Q = ("A" * 15) || 0x01. If the two exposed tag blocks are S_i || T_i,
    # then T_i = Enc(Q xor S_i). Among 257 responses, two S_i values must
    # share their final byte.
    seen: dict[int, tuple[bytes, bytes]] = {}

    for value in range(MAX_QUERIES):
        first_block = value.to_bytes(2, byteorder="big") + bytes(14)
        message = first_block + COMMON_SUFFIX
        response = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/oracle",
            {"message_hex": message.hex()},
        )
        tag_hex = response.get("tag_hex")
        tag = bytes.fromhex(tag_hex)

        state = tag[:BLOCK_SIZE]
        final = tag[BLOCK_SIZE:]
        collision = seen.get(state[-1])
        if collision is None:
            seen[state[-1]] = (first_block, state)
            continue

        first_block_1, state_1 = collision
        padded_suffix = COMMON_SUFFIX + b"\x01"
        forged_padded_block = bytes(
            suffix ^ state_1_byte ^ state_2_byte
            for suffix, state_1_byte, state_2_byte in zip(
                padded_suffix,
                state_1,
                state,
            )
        )

        # Equal final bytes in state_1 and state_2 leave the last byte of the
        # forged block equal to 0x01. Remove it from the submitted plaintext;
        # the server restores it when applying PKCS#7 padding. Starting from
        # state_1, the forged final block produces T_2, so the mixed tag is
        # S_1 || T_2.
        forged_message = first_block_1 + forged_padded_block[:-1]
        forged_tag = state_1 + final

        result = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/forge",
            {
                "message_hex": forged_message.hex(),
                "tag_hex": forged_tag.hex(),
            },
        )
        secret = result.get("secret")
        return secret
