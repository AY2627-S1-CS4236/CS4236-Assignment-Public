# CS4236 cumulative cryptography library

Each student or team keeps one repository for the semester. Students create and
own the cryptographic library and attack implementations. The instructor adds
only specifications, public tests, and vulnerable challenge applications.

## Repository ownership

You may freely modify:

- src/
- attacks/
- PROGRESS.md

Do not modify:

- course/
- .github/

New weekly material is delivered as a new course/weekXX/ directory. Weekly
updates never add or modify files under src/ or attacks/, so they should merge
without conflicting with student implementations.

## Layout

~~~text
pyproject.toml

src/
  educrypto/
    __init__.py          Student-owned library package

attacks/
  README.md              Student-owned attack modules are created here

course/
  README.md
  week01/
    README.md            Instructor-owned specification
    api.pyi              API description only
    test_*.py            Public tests
  weekXX/
    challenge/           Instructor-owned vulnerable application, when needed

.github/workflows/
  public-tests.yml       Cumulative public feedback

PROGRESS_TEMPLATE.md
~~~

No implementation stubs are released. A weekly specification tells students
which module to create, for example:

~~~text
src/educrypto/number_theory.py
~~~

Tests import the requested module inside test functions. A missing new module
therefore fails that week's tests without preventing pytest from collecting the
earlier weeks.

## Setup

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
~~~

On Windows, activate with:

~~~powershell
.venv\Scripts\activate
~~~

Run every released public test:

~~~bash
python -m pytest -q course
~~~

Or separate ordinary library feedback from attack feedback:

~~~bash
python -m pytest -q course -m "not attack"
python -m pytest -q course -m "attack"
~~~

Tests are feedback rather than a correctness-based grade. Effort is evidenced
by implementation attempts, commit history, test runs recorded in PROGRESS.md,
and short reflections.

## Planned progression

| Week | Student library work | Application misuse / attack |
|---:|---|---|
| 1 | Integer encoding and XOR | — |
| 2 | Extended GCD and modular inverses | — |
| 3 | Strict one-time-pad functions | Reused pad recovers a secret |
| 4 | PKCS#7 padding and AES-ECB | Observe deterministic equal blocks |
| 5 | AES-CBC | Padding-oracle plaintext recovery |

Later weeks can add CTR nonce reuse, hashes and length extension, textbook RSA,
or repeated signature nonces using exactly the same ownership model.

See [course/README.md](course/README.md) for the weekly contract and
[INSTRUCTOR_NOTES.md](INSTRUCTOR_NOTES.md) for distribution guidance.

