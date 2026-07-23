# ipc_server.py - Shared persistent socket server implementation

from typing import Callable
import socket
from common.framing import recv_frame, send_frame
from common.keygen import load_key_file


def run_server(
    host: str,
    port: int,
    key_file: str,
    encrypt_fn: Callable[..., bytes],
    decrypt_fn: Callable[..., bytes],
) -> None:
    key = load_key_file(key_file)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(1)

        print(f"SERVER listening on {host}:{port}", flush=True)

        while True:
            conn, addr = server_sock.accept()

            with conn:
                print(f"SERVER accepted connection from {addr}", flush=True)
                offset = 0

                while True:
                    try:
                        ciphertext = recv_frame(conn)
                    except ConnectionError:
                        print(f"SERVER connection from {addr} closed.", flush=True)
                        break

                    print(f"SERVER received ciphertext hex: {ciphertext.hex()}", flush=True)

                    plaintext = decrypt_fn(key, ciphertext, offset=offset)
                    offset = (offset + len(ciphertext)) % len(key)

                    print(
                        f"SERVER decrypted plaintext: {plaintext.decode('utf-8', errors='replace')}",
                        flush=True,
                    )

                    reply_plaintext = b"echo: " + plaintext
                    reply_ciphertext = encrypt_fn(key, reply_plaintext, offset=offset)
                    offset = (offset + len(reply_ciphertext)) % len(key)

                    print(f"SERVER reply plaintext: {reply_plaintext.decode('utf-8', errors='replace')}", flush=True)
                    print(f"SERVER reply ciphertext hex: {reply_ciphertext.hex()}", flush=True)

                    send_frame(conn, reply_ciphertext)
                    print("SERVER sent encrypted echo reply", flush=True)
