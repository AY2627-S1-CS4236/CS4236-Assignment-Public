# client.py

import argparse
from pathlib import Path
import socket
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from otp import decrypt, encrypt, load_key_file, split_key


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Receive exactly n bytes from a socket.
    """
    data = b""

    while len(data) < n:
        chunk = sock.recv(n - len(data))

        if not chunk:
            raise ConnectionError("socket closed before enough data was received")

        data += chunk

    return data


def recv_frame(sock: socket.socket) -> bytes:
    """
    Receive a length-prefixed frame.

    Frame format:
        [4-byte big-endian length][payload]
    """
    raw_length = recv_exact(sock, 4)
    length = struct.unpack(">I", raw_length)[0]

    return recv_exact(sock, length)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """
    Send a length-prefixed frame.

    Frame format:
        [4-byte big-endian length][payload]
    """
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def run_client(host: str, port: int, key_file: str, message: str) -> None:
    key = load_key_file(key_file)

    client_to_server_pad, server_to_client_pad = split_key(key)

    plaintext = message.encode("utf-8")
    ciphertext = encrypt(client_to_server_pad, plaintext)

    print(f"CLIENT plaintext: {message}", flush=True)
    print(f"CLIENT ciphertext hex: {ciphertext.hex()}", flush=True)

    with socket.create_connection((host, port), timeout=5) as sock:
        send_frame(sock, ciphertext)

        print("CLIENT sent encrypted message", flush=True)

        reply_ciphertext = recv_frame(sock)

        print(f"CLIENT received reply ciphertext hex: {reply_ciphertext.hex()}", flush=True)

        reply_plaintext = decrypt(server_to_client_pad, reply_ciphertext)

        print(
            f"CLIENT decrypted reply: {reply_plaintext.decode('utf-8', errors='replace')}",
            flush=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="OTP encrypted echo client")

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--message", required=True)

    args = parser.parse_args()

    run_client(args.host, args.port, args.key_file, args.message)


if __name__ == "__main__":
    main()