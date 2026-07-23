# server.py - Task 4 Server (Stream Cipher with Python Randomness & Global Offset)

import argparse
import random
import secrets
import socket


def generate_random_message() -> bytes:
    return secrets.token_hex(32).encode("utf-8")


MENU = (
    "====================================================\n"
    "  Task 4: Python PRNG Stream Cipher Service         \n"
    "====================================================\n"
    "1. Get Encrypted Challenge Message\n"
    "2. Encrypt Arbitrary Hex Message\n"
    "3. Submit Decrypted Secret Message\n"
    "4. Exit\n\n"
)


def generate_keystream(seed: int, length: int, offset: int = 0) -> bytes:
    rng = random.Random(seed)
    if offset > 0:
        rng.randbytes(offset)
    return rng.randbytes(length)


def encrypt(plaintext: bytes, seed: int, offset: int = 0) -> bytes:
    keystream = generate_keystream(seed, len(plaintext), offset=offset)
    return bytes(p ^ k for p, k in zip(plaintext, keystream))


def handle_client(conn: socket.socket) -> None:
    seed = random.randint(1, 2**32 - 1)
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
                ciphertext = encrypt(secret_message, seed, offset=offset)
                offset += len(secret_message)
                conn.sendall(f"Encrypted Challenge Message (hex): {ciphertext.hex()}\n".encode())

            elif choice == "2":
                conn.sendall(b"Enter message (hex) > ")
                msg_hex = conn.recv(65536).strip().decode("utf-8", errors="ignore")
                try:
                    plaintext = bytes.fromhex(msg_hex)
                    ciphertext = encrypt(plaintext, seed, offset=offset)
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
    parser = argparse.ArgumentParser(description="Task 4 Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9004)
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.port))
        s.listen(5)
        print(f"[TASK 4 SERVER] Listening on {args.host}:{args.port}", flush=True)
        while True:
            conn, addr = s.accept()
            with conn:
                handle_client(conn)


if __name__ == "__main__":
    main()
