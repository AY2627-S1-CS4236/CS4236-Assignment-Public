"""Sponge collision game server."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import threading
from typing import Iterator

from werkzeug.serving import WSGIRequestHandler, make_server

if __package__:
    from .application import create_app
else:
    from application import create_app


class QuietRequestHandler(WSGIRequestHandler):
    """Suppress per-request logs during automated challenge runs."""

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        return


@dataclass(frozen=True, slots=True)
class RunningServer:
    host: str
    port: int

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@contextmanager
def running_server(
    host: str = "127.0.0.1",
    port: int = 0,
    secret: str | None = None,
) -> Iterator[RunningServer]:
    """Run a temporary server and release its thread and socket afterward."""

    server = make_server(
        host,
        port,
        create_app(secret),
        threaded=True,
        request_handler=QuietRequestHandler,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield RunningServer(str(server.server_address[0]), int(server.server_port))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    app = create_app()
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
