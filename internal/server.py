# server.py

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


def run_server(host: str, port: int, key_file: str) -> None:
    key = load_key_file(key_file)

    client_to_server_pad, server_to_client_pad = split_key(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(1)

        print(f"SERVER listening on {host}:{port}", flush=True)

        while True:
            conn, addr = server_sock.accept()

            with conn:
                print(f"SERVER accepted connection from {addr}", flush=True)

                try:
                    ciphertext = recv_frame(conn)
                except ConnectionError:
                    print("SERVER socket closed before frame received (probe connection), waiting for next connection...", flush=True)
                    continue

                print(f"SERVER received ciphertext hex: {ciphertext.hex()}", flush=True)

                plaintext = decrypt(client_to_server_pad, ciphertext)

                print(
                    f"SERVER decrypted plaintext: {plaintext.decode('utf-8', errors='replace')}",
                    flush=True,
                )

                reply_plaintext = b"echo: " + plaintext
                reply_ciphertext = encrypt(server_to_client_pad, reply_plaintext)

                print(f"SERVER reply plaintext: {reply_plaintext.decode('utf-8', errors='replace')}", flush=True)
                print(f"SERVER reply ciphertext hex: {reply_ciphertext.hex()}", flush=True)

                send_frame(conn, reply_ciphertext)

                print("SERVER sent encrypted echo reply", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="OTP encrypted echo server")

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--key-file", required=True)

    args = parser.parse_args()

    run_server(args.host, args.port, args.key_file)


if __name__ == "__main__":
    main()