# CS4236 cryptography library — course material

This instructor repository publishes the material for each weekly assignment:

1. The library API and behavioral requirements.
2. Public feedback tests.
3. Vulnerable services and an attack exercise.

Implement the required `educrypto` modules in your own library repository.
Do not add your library implementation to this course-material repository.

After each lecture, the corresponding `course/weekXX` folder will be released.
The exact contents may vary.

## Weekly folder structure

~~~text
course/weekXX/
  README.md
  api.pyi
  test_weekXX.py
  challenge/                 # Present only when the week has a challenge
    README.md
    requirements.txt         # Present when extra dependencies are needed
    server.py
    application.py           # Names and internal structure may vary
~~~

Each file has a different role:

| Path | Purpose |
| --- | --- |
| `course/weekXX/README.md` | The main specification for that week. It describes the required modules, function behavior, edge cases, workflow, and test commands. Start here. |
| `course/weekXX/api.pyi` | A compact declaration of the public Python API: module names, function names, parameter types, and return types. It is an interface reference, not an implementation file. Create matching `.py` modules in your own library. |
| `course/weekXX/test_weekXX.py` | Public pytest feedback for the week's API. If there is a challenge, its solver test is marked `attack`; other challenge implementation details are not part of the public API tests. |
| `course/weekXX/challenge/README.md` | The challenge scenario, setup instructions, and required attack entry point. Read it before running or reviewing the service. |
| `course/weekXX/challenge/requirements.txt` | Extra packages required to run that challenge. Install these into the same Python environment used for your library and pytest. |
| `course/weekXX/challenge/server.py` | The command-line entry point for the vulnerable service. Tests may also use helpers from this file to start a temporary local server. |
| Other files under `challenge/` | The service implementation and any browser assets. Review these files to understand the application and find the vulnerability; they are not APIs that you need to reproduce in your library. |

The weekly README is the full behavioral specification. The `.pyi` file is a
quick signature reference, and the tests provide feedback on selected required
behavior. Passing only the visible examples should not replace implementing the
complete written specification.

## Recommended workflow

For each released week:

1. Read `course/weekXX/README.md` and `course/weekXX/api.pyi`.
2. Create the specified modules under `src/educrypto/` in your library
   repository.
3. Run the non-attack tests and finish the library API first.
4. If the week contains `challenge/`, follow its README, review the service,
   and implement the specified `educrypto.attacks.weekXX` entry point.
5. Run the attack test, then run the complete weekly test suite.

Challenge services may import the library API from the same week. An incomplete
library implementation can therefore prevent the service or attack test from
running correctly.

## Testing

Run every released public test:

~~~bash
python3 -m pytest -q course -s
~~~

Run one week, replacing `weekXX` with the released week number:

~~~bash
python3 -m pytest -q course/weekXX -s
~~~

Run ordinary library feedback without attack tests:

~~~bash
python3 -m pytest -q course -m "not attack" -s
~~~

Run only challenge attack tests:

~~~bash
python3 -m pytest -q course -m "attack" -s
~~~
