# Week 2 — Modular arithmetic

Create:

~~~text
src/educrypto/number_theory.py
~~~

## extended_gcd

~~~python
extended_gcd(a: int, b: int) -> tuple[int, int, int]
~~~

Return (g, x, y) such that:

~~~text
a*x + b*y = g = gcd(a, b)
~~~

- Support negative and zero inputs.
- g must be nonnegative.
- extended_gcd(0, 0) must return (0, 0, 0).
- Non-integer inputs raise TypeError.

## inverse_mod

~~~python
inverse_mod(a: int, modulus: int) -> int
~~~

- Return the unique inverse in [0, modulus).
- Raise ValueError when modulus <= 0.
- Raise ValueError when the inverse does not exist.
- Non-integer inputs raise TypeError.

Examples:

~~~python
extended_gcd(240, 46) == (2, -9, 47)
inverse_mod(3, 11) == 4
~~~

Other valid Bezout coefficients are acceptable when they satisfy the identity.

Run:

~~~bash
python -m pytest -q course/week02
~~~

