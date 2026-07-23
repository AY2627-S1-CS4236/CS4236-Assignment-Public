# Task 4: Python PRNG Stream Cipher Service

## Overview
This task demonstrates the security risks of using non-cryptographic Pseudo-Random Number Generators (PRNGs) such as Python's standard `random` module (Mersenne Twister MT19937) for stream cipher encryption.

The server provides an interactive TCP interface with the following options:
1. **Get Encrypted Challenge Message**: Returns the encrypted secret challenge message hex for this connection.
2. **Encrypt Arbitrary Hex Message**: Allows the user to request encryption of any arbitrary hex message.
3. **Submit Decrypted Secret Message**: Submits the decrypted secret message for server verification.

## Running the Server

### Option A: Local Python Execution
```bash
python server.py --port 9004
```

### Option B: Docker Deployment
```bash
docker-compose up --build -d
```

## Running the Attack Script
```bash
python solver.py --host 127.0.0.1 --port 9004
```
