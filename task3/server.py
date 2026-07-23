# server.py - Task 3 Server (Repeating Key OTP with Global Offset)

import argparse
import os
import secrets
import socket


def generate_random_message() -> bytes:
    # Generate a random hex message (64 hex characters = 32 random bytes)
    return secrets.token_hex(32).encode("utf-8")


MENU = (
    "====================================================\n"
    "  Task 3: Repeating Key OTP Encryption Service      \n"
    "====================================================\n"
    "1. Get Encrypted Challenge Message\n"
    "2. Encrypt Arbitrary Hex Message\n"
    "3. Submit Decrypted Secret Message\n"
    "4. Exit\n\n"
)


def xor_bytes(data: bytes, key: bytes, offset: int = 0) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[(offset + i) % key_len] for i, b in enumerate(data))


def handle_client(conn: socket.socket) -> None:
    # Random key, random message, and global offset per connection session
    key = os.urandom(16)
    secret_message = generate_random_message()
    offset = 0

    conn.sendall(MENU.encode())

    while True:
        try:
            conn.sendall(b"Choice > ")
            raw = conn.recv(1024).strip()
            if not raw:
                break
            choice = raw.decode("utf-8", errors="ignore").strip()

            if choice == "1":
                ciphertext = xor_bytes(secret_message, key, offset=offset)
                offset += len(secret_message)
                conn.sendall(f"Encrypted Challenge Message (hex): {ciphertext.hex()}\n".encode())

            elif choice == "2":
                conn.sendall(b"Enter message (hex) > ")
                msg_hex = conn.recv(65536).strip().decode("utf-8", errors="ignore")
                try:
                    plaintext = bytes.fromhex(msg_hex)
                    ciphertext = xor_bytes(plaintext, key, offset=offset)
                    offset += len(plaintext)
                    conn.sendall(f"Ciphertext (hex): {ciphertext.hex()}\n".encode())
                except ValueError:
                    conn.sendall(b"Error: Invalid hex input.\n")

            elif choice == "3":
                conn.sendall(b"Enter decrypted message > ")
                user_msg = conn.recv(1024).strip().decode("utf-8", errors="ignore")
                if user_msg == secret_message.decode():
                    conn.sendall(f"[SUCCESS] Verification successful! You decrypted the message: \"{secret_message.decode()}\"\n".encode())
                else:
                    conn.sendall(b"[FAIL] Incorrect message. Try again!\n")

            elif choice in ("4", "exit", "quit"):
                conn.sendall(b"Goodbye!\n")
                break

        except Exception as e:
            conn.sendall(f"Error: {e}\n".encode())
            break


def main():
    parser = argparse.ArgumentParser(description="Task 3 Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9003)
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.port))
        s.listen(5)
        print(f"[TASK 3 SERVER] Listening on {args.host}:{args.port}", flush=True)
        while True:
            conn, addr = s.accept()
            with conn:
                handle_client(conn)


if __name__ == "__main__":
    main()
