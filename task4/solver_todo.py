# solver.py - Task 4 Attack Script (Python PRNG Stream Cipher Attack with MT19937 State Recovery)

import argparse
import socket

def recv_until(sock: socket.socket, target: bytes) -> str:
    data = b""
    while target not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="replace")


def solve_task3(host: str, port: int) -> bool:
    print(f"[ATTACK] Connecting to server at {host}:{port}...")

    with socket.create_connection((host, port), timeout=5) as sock:
        recv_until(sock, b"Choice > ")
        
        # TODO: Implement Attack

        return False


def main():
    parser = argparse.ArgumentParser(description="Task 3 Attack Script")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9003, help="Target port (default: 9003)")
    args = parser.parse_args()

    success = solve_task3(args.host, args.port)
    if success:
        print("[RESULT] Task 3 Attack Executed Successfully!")
    else:
        print("[RESULT] Task 3 Attack Failed!")


if __name__ == "__main__":
    main()
