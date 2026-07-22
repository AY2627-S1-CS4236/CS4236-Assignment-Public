# test_otp_ipc.py

import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path

HOST = "127.0.0.1"
PORT = "9001"


def wait_for_port(host: str, port: int, timeout: float = 3.0) -> None:
    start = time.time()

    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)

    raise TimeoutError(f"server did not start on {host}:{port}")


def run_client_message(
    internal_dir: Path, key_path: Path, message: str, host: str = HOST, port: str = PORT
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(internal_dir / "client.py"),
            "--host",
            host,
            "--port",
            port,
            "--key-file",
            str(key_path),
            "--message",
            message,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
    )


def main():
    parser = argparse.ArgumentParser(description="OTP IPC Test Runner & Interactive Console")
    parser.add_argument(
        "--generate-key",
        action="store_true",
        default=False,
        help="Run keygen.py to generate a new key file before testing (default: False)",
    )
    parser.add_argument(
        "--key-file",
        default="key.bin",
        help="Path to the key file to use (default: key.bin)",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=4096,
        help="Size of key to generate if --generate-key is set (default: 4096)",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=3,
        help="Number of automated test rounds before interactive mode (default: 3)",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        default=False,
        help="Skip interactive mode after automated rounds",
    )

    args = parser.parse_args()
    key_path = Path(args.key_file)
    internal_dir = Path(__file__).parent / "internal"
    keygen_script = internal_dir / "keygen.py"

    if args.generate_key:
        print(f"Generating new key using keygen.py at {key_path}...")
        subprocess.run(
            [
                sys.executable,
                str(keygen_script),
                "--out",
                str(key_path),
                "--size",
                str(args.size),
            ],
            check=True,
        )
    else:
        if not key_path.exists():
            print(
                f"[WARNING] Key file {key_path} does not exist. Generating a default key for test..."
            )
            subprocess.run(
                [
                    sys.executable,
                    str(keygen_script),
                    "--out",
                    str(key_path),
                    "--size",
                    str(args.size),
                ],
                check=True,
            )
        else:
            print(f"Using existing key file: {key_path}")

    server = subprocess.Popen(
        [
            sys.executable,
            str(internal_dir / "server.py"),
            "--host",
            HOST,
            "--port",
            PORT,
            "--key-file",
            str(key_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        wait_for_port(HOST, int(PORT))
        print(f"\n--- Starting {args.rounds} Automated Test Rounds ---")

        all_passed = True
        for i in range(1, args.rounds + 1):
            test_msg = f"hello from tester (round {i})"
            print(f"\n[Round {i}/{args.rounds}] Sending: '{test_msg}'")

            client = run_client_message(internal_dir, key_path, test_msg)
            expected = "echo: " + test_msg

            if expected in client.stdout:
                print(f"[PASS] Round {i}: Client received expected echo response.")
            else:
                print(f"[CHECK] Round {i}: Expected response missing in output.")
                print(f"Stdout:\n{client.stdout}")
                all_passed = False

            if client.returncode != 0:
                print(f"[CHECK] Round {i}: Client exited with code {client.returncode}.")
                if client.stderr:
                    print(f"Stderr:\n{client.stderr}")
                all_passed = False

        if all_passed:
            print(f"\n[PASS] All {args.rounds} automated rounds completed successfully!")

        if not args.non_interactive:
            print("\n" + "=" * 70)
            print("AUTOMATED TEST ROUNDS COMPLETE -> ENTERING INTERACTIVE MODE")
            print("Type a message and press Enter to send to server.")
            print("Type 'exit' or 'quit' (or Ctrl+C) to terminate.")
            print("=" * 70)

            while True:
                try:
                    user_msg = input("\nEnter message to send > ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\nExiting interactive mode...")
                    break

                if not user_msg:
                    continue
                if user_msg.lower() in ("exit", "quit"):
                    print("Exiting interactive mode...")
                    break

                client = run_client_message(internal_dir, key_path, user_msg)
                print("\n=== Client stdout ===")
                print(client.stdout.strip())
                if client.stderr.strip():
                    print("=== Client stderr ===")
                    print(client.stderr.strip())

    finally:
        server.terminate()

        try:
            server_stdout, server_stderr = server.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
            server_stdout, server_stderr = server.communicate()

        print("\n=== Server Shutdown Logs ===")
        if server_stdout.strip():
            print("Server stdout:\n" + server_stdout.strip())
        if server_stderr.strip():
            print("Server stderr:\n" + server_stderr.strip())


if __name__ == "__main__":
    main()