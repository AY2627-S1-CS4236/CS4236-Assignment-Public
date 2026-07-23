# framing.py - Socket framing helpers

import socket
import struct


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
    Receive a length-prefixed frame [4-byte big-endian length][payload].
    """
    raw_length = recv_exact(sock, 4)
    length = struct.unpack(">I", raw_length)[0]

    return recv_exact(sock, length)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """
    Send a length-prefixed frame [4-byte big-endian length][payload].
    """
    sock.sendall(struct.pack(">I", len(payload)) + payload)
