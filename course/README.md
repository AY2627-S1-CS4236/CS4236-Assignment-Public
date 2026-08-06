# Instructor-owned course material

Do not edit this directory. Each week is an additive release containing the
public API contract, tests, and—when useful—a vulnerable local application.

A week may contain:

~~~text
course/weekXX/
  README.md
  api.pyi
  test_api.py
  test_correctness.py
  challenge/
    README.md
    server.py
    client.py
    test_attack.py
~~~

The api.pyi files describe interfaces only. They are deliberately outside src/
and are not implementation stubs.

All tests are public. Run one week with:

~~~bash
python -m pytest -q course/week03
~~~

Run all material released so far with:

~~~bash
python -m pytest -q course
~~~

Weekly distribution should add exactly one new course/weekXX/ directory. It
must not modify src/, attacks/, or any earlier course/weekXX/ directory.

