# client.py - Task 2 persistent client entrypoint

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from common.ipc_client import run_persistent_client
from task2.stream_cipher import decrypt, encrypt


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="OTP encrypted echo client (persistent mode)")

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--message", default=None, help="Single message to send")
    parser.add_argument(
        "--rounds",
        type=int,
        default=0,
        help="Number of automated test rounds over persistent connection",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        default=False,
        help="Run interactive input mode over persistent connection",
    )

    args = parser.parse_args()

    run_persistent_client(
        args.host,
        args.port,
        args.key_file,
        encrypt_fn=encrypt,
        decrypt_fn=decrypt,
        message=args.message,
        rounds=args.rounds,
        interactive=args.interactive,
    )


if __name__ == "__main__":
    main()