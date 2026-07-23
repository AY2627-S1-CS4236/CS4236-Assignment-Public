# server.py - Task 1 persistent server entrypoint

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from common.ipc_server import run_server
from otp import decrypt, encrypt


def main() -> None:
    parser = argparse.ArgumentParser(description="OTP encrypted echo server")

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--key-file", required=True)

    args = parser.parse_args()

    run_server(args.host, args.port, args.key_file, encrypt_fn=encrypt, decrypt_fn=decrypt)


if __name__ == "__main__":
    main()