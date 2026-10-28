"""Instructor reference attack for the related-nonce Schnorr service."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen

from educrypto.dh import DHParameters, DHPrivateKey
from educrypto.hashing import sponge_hash
from educrypto.schnorr import sign


def _post_json(
    base_url: str, path: str, payload: dict[str, object] | None = None
) -> dict[str, object]:
    request = Request(
        f"{base_url.rstrip('/')}/{path.lstrip('/')}",
        data=b"" if payload is None else json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def _challenge(parameters: DHParameters, R: int, message: bytes) -> int:
    width = (parameters.p.bit_length() + 7) // 8
    digest = sponge_hash(
        R.to_bytes(width, "big") + message,
        c=8, digest_length=32, rounds=20,
    )
    return int.from_bytes(digest, "big") % parameters.q


def solve(base_url: str) -> str:
    game = _post_json(base_url, "/api/v1/games")
    parameters = DHParameters(int(game["p"]), int(game["g"]), int(game["q"]))
    game_id = game["game_id"]
    previous = None
    index = 0
    while True:
        message = f"Week 10 signing query {index}".encode("ascii")
        result = _post_json(
            base_url, f"/api/v1/games/{game_id}/oracle",
            {"message_hex": message.hex()},
        )
        r = _challenge(parameters, int(result["R"]), message)
        s = int(result["s"])
        if previous is not None:
            r_before, s_before = previous
            difference = (r - r_before) % parameters.q
            if difference:
                # s2-s1 = 10 + (r2-r1)*x, including nonce wraparound.
                x = (s - s_before - 10) * pow(difference, -1, parameters.q)
                x %= parameters.q
                if pow(parameters.g, x, parameters.p) != int(game["y"]):
                    raise RuntimeError("the recovered exponent does not match the public key")
                break
        # If challenges coincide, use the next consecutive pair so the nonce
        # difference stays exactly 10 modulo q.
        previous = (r, s)
        index += 1

    fresh = b"Week 10 fresh-message forgery"
    signature = sign(DHPrivateKey(parameters, x), fresh)
    result = _post_json(
        base_url, f"/api/v1/games/{game_id}/forge",
        {"message_hex": fresh.hex(), "R": str(signature.R), "s": str(signature.s)},
    )
    if not result["valid"] or not result["fresh"] or not result["game"]["complete"]:
        raise RuntimeError("the reference forgery was rejected")
    return result["secret"]
