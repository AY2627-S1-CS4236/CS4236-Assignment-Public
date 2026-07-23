# test_harness.py - Shared test runner harness for OTP IPC testing

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

HOST = "127.0.0.1"
PORT = "9001"


def wait_for_server_ready(log_path: Path, timeout: float = 10.0) -> None:
    start = time.time()
    while time.time() - start < timeout:
        if log_path.exists():
            content = log_path.read_text(encoding="utf-8", errors="replace")
            if "SERVER listening on" in content:
                time.sleep(0.1)
                return
        time.sleep(0.05)
    raise TimeoutError("Server process failed to start listening within timeout.")


def run_ipc_test_suite(
    args,
    task_dir: Path,
    alg_passed: bool = True,
) -> None:
    key_path = Path(args.key_file).resolve()
    internal_dir = task_dir / "internal"
    keygen_script = internal_dir / "keygen.py"

    print("[INIT] Starting OTP IPC Test Suite...")

    if args.generate_key:
        print(f"\n[KEYGEN] Generating new key using keygen.py at {key_path}...")
        subprocess.run(
            [
                sys.executable,
                str(keygen_script),
                "--out",
                str(key_path),
                "--size",
                str(args.size),
            ],
            cwd=task_dir,
            check=True,
        )
    else:
        if not key_path.exists():
            print(
                f"\n[WARNING] Key file {key_path} does not exist. Generating default key..."
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
                cwd=task_dir,
                check=True,
            )
        else:
            print(f"\n[KEY] Using existing key file: {key_path}")

    # Use a temporary log file for server stdout/stderr to avoid pipe buffer deadlocks
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8") as server_log:
        server_log_path = Path(server_log.name)

    server_log_file = open(server_log_path, "w", encoding="utf-8")

    print("[SERVER] Launching persistent OTP echo server...")
    server = subprocess.Popen(
        [
            sys.executable,
            "-u",
            str(internal_dir / "server.py"),
            "--host",
            HOST,
            "--port",
            PORT,
            "--key-file",
            str(key_path),
        ],
        cwd=task_dir,
        stdout=server_log_file,
        stderr=subprocess.STDOUT,
    )

    client_stdout, client_stderr = "", ""
    client_returncode = 0

    try:
        wait_for_server_ready(server_log_path)
        print("[SERVER] Server active and listening on port 9001.")

        # Phase 1: Automated Verification Rounds
        if args.rounds > 0:
            client_cmd_verify = [
                sys.executable,
                "-u",
                str(internal_dir / "client.py"),
                "--host",
                HOST,
                "--port",
                PORT,
                "--key-file",
                str(key_path),
                "--rounds",
                str(args.rounds),
            ]

            print(f"[CLIENT] Running {args.rounds} automated verification rounds...")
            client_proc = subprocess.run(
                client_cmd_verify,
                cwd=task_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            client_stdout = client_proc.stdout
            client_stderr = client_proc.stderr
            client_returncode = client_proc.returncode

            server_log_file.flush()
            server_stdout = server_log_path.read_text(encoding="utf-8", errors="replace")

            # Verification Summary Banner
            print("\n" + "=" * 70)
            print("[TEST CASE VERIFICATION SUMMARY]")
            print("=" * 70)

            all_passed = alg_passed
            for i in range(1, args.rounds + 1):
                expected_client_sent = f"CLIENT plaintext: hello from tester (round {i})"
                expected_client_received = f"CLIENT decrypted reply: echo: hello from tester (round {i})"
                expected_server_decrypted = f"SERVER decrypted plaintext: hello from tester (round {i})"
                expected_server_reply = f"SERVER reply plaintext: echo: hello from tester (round {i})"

                c_sent_ok = expected_client_sent in client_stdout
                c_recv_ok = expected_client_received in client_stdout
                s_dec_ok = expected_server_decrypted in server_stdout
                s_reply_ok = expected_server_reply in server_stdout

                round_passed = c_sent_ok and c_recv_ok and s_dec_ok and s_reply_ok

                if round_passed:
                    print(
                        f"[PASS] ✔ Test Case Round {i}/{args.rounds}: Client sent, Server decrypted, and Client received expected echo reply!"
                    )
                else:
                    all_passed = False
                    print(
                        f"[FAIL] ✖ Test Case Round {i}/{args.rounds}: Output verification failed!"
                    )

            if client_returncode != 0:
                all_passed = False
                print(f"[FAIL] ✖ Client process exited with error code {client_returncode}")

            print("=" * 70)
            if all_passed:
                print("[FINAL RESULT] ✔ ALL TEST CASES PASSED SUCCESSFULLY!")
            else:
                print("[FINAL RESULT] ✖ TEST SUITE FAILED!")
                if client_stderr.strip():
                    print(f"\n--- Client Stderr ---\n{client_stderr.strip()}")
                if server_stdout.strip():
                    print(f"\n--- Server Output ---\n{server_stdout.strip()}")
            print("=" * 70 + "\n")

        # Phase 2: Interactive Mode (if not non-interactive)
        if not args.non_interactive:
            print("=" * 70)
            print("[INTERACTIVE] ENTERING INTERACTIVE CLIENT CONSOLE")
            print("Type a message and press Enter to send over persistent socket.")
            print("Type 'exit' or 'quit' (or Ctrl+C) to terminate.")
            print("=" * 70 + "\n")

            interactive_cmd = [
                sys.executable,
                "-u",
                str(internal_dir / "client.py"),
                "--host",
                HOST,
                "--port",
                PORT,
                "--key-file",
                str(key_path),
                "--interactive",
            ]
            subprocess.run(interactive_cmd)

    finally:
        server.terminate()
        try:
            server.wait(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()

        server_log_file.close()
        try:
            os.remove(server_log_path)
        except OSError:
            pass
