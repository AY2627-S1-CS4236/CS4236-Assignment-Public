# ipc_client.py - Shared persistent socket client implementation

import socket
import time
from typing import Any, Callable
from common.framing import recv_frame, send_frame
from common.keygen import load_key_file


def send_msg_over_sock(
    sock: socket.socket,
    message: str,
    key: bytes,
    offset: int,
    encrypt_fn: Callable[..., bytes],
    decrypt_fn: Callable[..., bytes],
) -> tuple[int, str]:
    plaintext = message.encode("utf-8")
    ciphertext = encrypt_fn(key, plaintext, offset=offset)
    offset = (offset + len(ciphertext)) % len(key)

    print(f"CLIENT plaintext: {message}", flush=True)
    print(f"CLIENT ciphertext hex: {ciphertext.hex()}", flush=True)

    send_frame(sock, ciphertext)
    print("CLIENT sent encrypted message", flush=True)

    reply_ciphertext = recv_frame(sock)
    print(f"CLIENT received reply ciphertext hex: {reply_ciphertext.hex()}", flush=True)

    reply_plaintext = decrypt_fn(key, reply_ciphertext, offset=offset)
    offset = (offset + len(reply_ciphertext)) % len(key)

    reply_str = reply_plaintext.decode("utf-8", errors="replace")
    print(f"CLIENT decrypted reply: {reply_str}", flush=True)

    expected_reply = f"echo: {message}"
    if reply_str == expected_reply:
        print(f"[PASS] ✔ Test Case Verification: Server reply matches expected '{expected_reply}'", flush=True)
    else:
        print(f"[FAIL] ✖ Test Case Verification: Server reply mismatch!", flush=True)
        print(f"       Expected: '{expected_reply}'", flush=True)
        print(f"       Received: '{reply_str}'", flush=True)

    return offset, reply_str


def run_persistent_client(
    host: str,
    port: int,
    key_file: str,
    encrypt_fn: Callable[..., bytes],
    decrypt_fn: Callable[..., bytes],
    message: str | None = None,
    rounds: int = 0,
    interactive: bool = False,
) -> None:
    key = load_key_file(key_file)
    offset = 0

    sock = None
    start_time = time.time()
    while time.time() - start_time < 10.0:
        try:
            sock = socket.create_connection((host, port), timeout=10)
            break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)

    if sock is None:
        sock = socket.create_connection((host, port), timeout=10)

    with sock:
        if message:
            offset, _ = send_msg_over_sock(sock, message, key, offset, encrypt_fn, decrypt_fn)

        if rounds > 0:
            print(f"\n--- Running {rounds} Automated Rounds over Persistent Socket ---", flush=True)
            for i in range(1, rounds + 1):
                test_msg = f"hello from tester (round {i})"
                print(f"\n[Round {i}/{rounds}]", flush=True)
                offset, _ = send_msg_over_sock(sock, test_msg, key, offset, encrypt_fn, decrypt_fn)

        if interactive:
            print("\n" + "=" * 70, flush=True)
            print("PERSISTENT CLIENT CONNECTED -> INTERACTIVE MODE", flush=True)
            print("Type a message and press Enter to send over open socket.", flush=True)
            print("Type 'exit' or 'quit' to close connection.", flush=True)
            print("=" * 70, flush=True)

            while True:
                try:
                    user_msg = input("\nEnter message to send > ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\nClosing client connection...", flush=True)
                    break

                if not user_msg:
                    continue
                if user_msg.lower() in ("exit", "quit"):
                    print("Closing client connection...", flush=True)
                    break

                offset, reply_str = send_msg_over_sock(sock, user_msg, key, offset, encrypt_fn, decrypt_fn)
                print(f"--> Server Response: {reply_str}", flush=True)
