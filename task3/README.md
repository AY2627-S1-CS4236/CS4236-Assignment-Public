# Task 3: Repeating Key OTP Encryption Service

## Overview
This task demonstrates the vulnerability of One-Time Pad (OTP) key reuse (Many-Time Pad attack). The server uses a fixed, repeated key to encrypt plaintexts using XOR logic.

The server provides an interactive TCP interface with the following options:
1. **Get Encrypted Challenge Message**: Returns the encrypted secret challenge message hex.
2. **Encrypt Arbitrary Hex Message**: Allows the user to request encryption of any arbitrary hex message.
3. **Submit Decrypted Secret Message**: Submits the decrypted secret message for server verification.

## Running the Server

### Option A: Local Python Execution
```bash
python server.py --port 9003
```

### Option B: Docker Deployment
```bash
docker-compose up --build -d
```

## Running the Attack Script
```bash
python solver.py --host 127.0.0.1 --port 9003
```
