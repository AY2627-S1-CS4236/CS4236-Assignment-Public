# SeedSafe

SeedSafe is a small encrypted-backup service developed by a junior programmer.
After learning about substitution-permutation networks, the programmer
replaced the service's original encryption code with a custom 128-bit block
cipher. The service gives each customer a recovery seed, keeps no copy of that
seed, and makes the encrypted archive public for transparency.

Review the implementation and identify the issues with the application.
Develop an attack script by creating
`src/educrypto/attacks/week02.py` in your library and implement:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

## Setup

### macOS and Linux

From the course-material repository, enter the challenge directory and install
the server dependency:

~~~bash
cd course/week02/challenge
python3 -m pip install -r requirements.txt
~~~

Start the service:

~~~bash
SECRET='replace-me' python3 server.py
~~~

Then open `http://127.0.0.1:8000`.

### Windows PowerShell

From the course-material repository, enter the challenge directory and install
the server dependency with the Windows Python launcher:

~~~powershell
Set-Location course/week02/challenge
py -m pip install -r requirements.txt
~~~

Set the startup secret and run the service:

~~~powershell
$env:SECRET = 'replace-me'
py server.py
~~~

Then open `http://127.0.0.1:8000`.

Before running the server, make sure you have implemented the Week 2
`educrypto.spn` API. The challenge service imports that implementation.

## Application S-box

SeedSafe uses a byte-oriented S-box. Split each input byte into its first four
bits (the high nibble, `H`) and last four bits (the low nibble, `L`). The
substitution is:

~~~text
S(H || L) = (H XOR L) || L
~~~

In other words, the first four output bits are the XOR of the input's first
and last four bits, while the last four output bits are unchanged. For
example, `S(0xA3) = 0x93`. This S-box is its own inverse.

## Testing

From the course-material repository root, run the attack feedback with:

~~~bash
python3 -m pytest -q course/week02 -m "attack" -s
~~~

In Windows PowerShell, run:

~~~powershell
py -m pytest -q course/week02 -m "attack" -s
~~~

The server started manually on port 8000 is only for your own exploration. When
the attack test runs, pytest creates a separate temporary SeedSafe service on
an automatically selected available port. It does not send requests to an
existing service on port 8000. The test passes the temporary service's complete
URL to `solve(base_url)` and shuts that service down after the test finishes.

Do not hard-code a hostname or port in the attack implementation. Build every
request URL from the `base_url` argument supplied to `solve`. The function must
return the exact startup secret and must not start another server.

## Tips and helpers

When SeedSafe starts, it encrypts the application's secret and stores the
result as a backup record. Start your code review with `service.py`. It shows
how the Week 2 primitives are configured and assembled. Follow the secret
through that code, then inspect the HTTP application and browser code to learn
which encrypted data and operations are exposed to a client.

### HTTP requests

The third-party [Requests](https://requests.readthedocs.io/) package provides a
convenient HTTP client. It is optional and can be installed with pip:

~~~bash
python3 -m pip install requests
~~~

In Windows PowerShell, run:

~~~powershell
py -m pip install requests
~~~

These helpers send JSON requests without hard-coding the server address:

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

Useful conversion helpers include:

- `bytes.fromhex(value)` to decode hexadecimal data;
- `data.hex()` to encode bytes as hexadecimal;
- `text.encode("utf-8")` to convert text to bytes; and
- `data.decode("utf-8")` to convert UTF-8 bytes back to text.

Inspect `static/app.js` and the Python service files for the available routes,
request bodies, and response fields.
