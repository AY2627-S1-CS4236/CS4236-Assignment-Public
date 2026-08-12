# SeedSafe

SeedSafe is a small encrypted-backup service developed by a junior programmer.
It gives each customer a recovery seed, keeps no copy of that seed, and makes
the encrypted archive public for transparency.

Review the implementation and identify the issues with the application.
Develop an attack script by creating
`src/educrypto/attacks/week01.py` in your library and implement:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

## Setup

From the course-material repository, enter the challenge directory and install
the server dependency:

~~~bash
cd course/week01/challenge
python3 -m pip install -r requirements.txt
~~~

Start the service:

~~~bash
SECRET='replace-me' python3 server.py
~~~

Then open `http://127.0.0.1:8000`.

Before running the server, make sure you have implemented the library APIs for
this week.

## HTTP and byte helpers

Your `solve` function needs to communicate with the running HTTP service. The
third-party [Requests](https://requests.readthedocs.io/) package provides a
convenient Python client. It is optional and can be installed with pip:

~~~bash
python3 -m pip install requests
~~~

The package is installed as `requests`. The following helpers show how to send
JSON requests without hard-coding the server's host or port:

~~~python
import requests


def get_json(base_url: str, path: str) -> dict:
    response = requests.get(
        f"{base_url.rstrip('/')}/{path.lstrip('/')}",
        timeout=5,
    )
    response.raise_for_status()
    return response.json()


def post_json(base_url: str, path: str, payload: dict) -> dict:
    response = requests.post(
        f"{base_url.rstrip('/')}/{path.lstrip('/')}",
        json=payload,
        timeout=5,
    )
    response.raise_for_status()
    return response.json()
~~~

Useful Requests operations include:

- `requests.get(url, timeout=5)` for a GET request;
- `requests.post(url, json=payload, timeout=5)` for a JSON POST request;
- `response.json()` to decode a JSON response; and
- `response.raise_for_status()` to turn an HTTP error response into an
  exception.

The standard library also contains useful conversion helpers:

- `bytes.fromhex(value)` converts a hexadecimal string to bytes;
- `data.hex()` converts bytes to a hexadecimal string;
- `text.encode("utf-8")` converts text to bytes; and
- `data.decode("utf-8")` converts UTF-8 bytes back to text.

Inspect `static/app.js` and the Python service files to determine which routes,
request bodies, and response fields are available. The attack test supplies a
`base_url`, often with a random port, so `solve` must use that argument instead
of assuming `http://127.0.0.1:8000`.

## Testing

From the course-material repository root, run the attack test with:

~~~bash
python3 -m pytest -q course/week01 -m "attack"
~~~

The server started manually on port 8000 is only for your own exploration. When
the attack test runs, pytest creates a separate temporary SeedSafe service on
an automatically selected available port. It does not send requests to an
existing service on port 8000. The test passes the temporary service's complete
URL to `solve(base_url)` and shuts that service down after the test finishes.

Therefore, do not hard-code a hostname or port in the attack implementation.
Build every request URL from the `base_url` argument supplied to `solve`.
