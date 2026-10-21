"""Reference attack for the Week 08 ElGamal CPA game."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen


MAX_SMALL_ORDER = 1 << 15


def _post_json(
    base_url: str, path: str, payload: dict[str, object] | None = None
) -> dict[str, object]:
    data = b"" if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{base_url.rstrip('/')}/{path.lstrip('/')}",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def _subgroup_elements(p: int, g: int) -> set[int]:
    """Include every possible power because the generator order is < 2^15."""

    elements = set()
    value = 1
    for _ in range(MAX_SMALL_ORDER):
        elements.add(value)
        value = value * g % p
    return elements


def solve(base_url: str) -> str:
    game = _post_json(base_url, "/api/v1/games")
    game_id = game["game_id"]
    subgroup = _subgroup_elements(int(game["p"]), int(game["g"]))

    for _ in range(int(game["wins_required"])):
        ciphertext = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/challenge",
            {"left": "1", "right": "2"},
        )
        guess = 0 if int(ciphertext["c2"]) in subgroup else 1
        result = _post_json(
            base_url,
            f"/api/v1/games/{game_id}/guess",
            {"guess": guess},
        )
        if not result["correct"]:
            raise RuntimeError("the subgroup membership guess failed")
        if result["complete"]:
            return result["secret"]

    raise RuntimeError("the game ended without revealing the secret")
