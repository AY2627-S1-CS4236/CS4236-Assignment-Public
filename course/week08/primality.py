"""Supplied Week 08 probable-prime test.

Copy this file to src/educrypto/primality.py in your library repository.
It uses Miller–Rabin and Python's built-in three-argument pow;
"""

import secrets


_SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
)
_MILLER_RABIN_ROUNDS = 32


def is_probable_prime(n: int) -> bool:
    """Return whether n passes 32 random Miller–Rabin rounds."""

    if n < 2:
        return False
    for prime in _SMALL_PRIMES:
        if n % prime == 0:
            return n == prime

    # Write n - 1 = 2**s * d, with d odd.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(_MILLER_RABIN_ROUNDS):
        base = secrets.randbelow(n - 3) + 2
        value = pow(base, d, n)
        if value in (1, n - 1):
            continue
        for _ in range(s - 1):
            value = pow(value, 2, n)
            if value == n - 1:
                break
        else:
            return False
    return True
