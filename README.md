# SRFT — Secure Reliable File Transfer

A custom UDP-based file transfer protocol built from scratch using raw sockets (SOCK_RAW). Implements reliable data transfer with Go-Back-N sliding window protocol and comprehensive security features including end-to-end encryption, authentication, and replay protection.

## Features

**Phase 1 — Reliable File Transfer:**

- Raw socket implementation with custom IP/UDP header construction
- Go-Back-N (GBN) sliding window protocol with configurable window size (128 packets)
- Timeout-based retransmission and fast retransmit on 3 duplicate ACKs
- Cumulative ACK with delayed ACK optimization (ACK every 16 packets or 10ms)
- Out-of-order packet handling and duplicate detection
- Internet checksum for packet integrity verification
- Transfer statistics and performance reporting

**Phase 2 — Secure File Transfer:**

- HMAC-based secure handshake (ClientHello/ServerHello) with pre-shared key (PSK)
- End-to-end encryption using AES-GCM AEAD (Authenticated Encryption with Associated Data)
- HKDF-SHA256 key derivation for session keys
- Sliding-window bitmap-based replay protection
- SHA-256 file integrity verification
- Built-in attack simulator for security testing (tamper, replay, inject modes)
- Comprehensive security metrics reporting (AEAD failures, replay drops)
- Optional insecure mode (`--insecure`) for testing without encryption

**Testing:**

- 108 unit and integration tests covering all protocol and security components
- Phase 1 and Phase 2 test reports with performance benchmarks
- Tested with files up to 1GB and various packet loss scenarios (0%-4%)

---

## How to run

### Requirements

- Python 3.12+
- Administrator/root privileges (required for raw sockets)
- Both machines must have ports 12345 and 12346 open for UDP traffic

### Starting the server

Run on the server machine with administrator/root privileges:

```bash
# Basic usage:
# python SRFT_UDPServer.py <server_ip> [files_directory] [--insecure] [--attack {tamper,replay,inject}]

# Windows (run PowerShell as Administrator):
cd src
python SRFT_UDPServer.py 127.0.0.1 ./test_files

# Linux/AWS EC2:
cd src
sudo python SRFT_UDPServer.py 192.168.1.10

# Run without encryption (Phase 1 mode):
python SRFT_UDPServer.py 127.0.0.1 ./test_files --insecure

# Run with simulated security attacks:
python SRFT_UDPServer.py 127.0.0.1 ./test_files --attack tamper
```

### Starting the client

Before running, set the server IP address and the client IP address in `config.py`:

```python
SERVER_IP = "127.0.0.1"  # use 127.0.0.1 for local testing
                         # replace with server EC2 private IP for AWS testing
CLIENT_IP = "127.0.0.1"  # use 127.0.0.1 for local testing
                         # replace with client EC2 private IP for AWS testing
```

Run on the client machine with administrator/root privileges:

```bash
# Basic usage:
# python SRFT_UDPClient.py <filename> [--insecure]

# Windows (run PowerShell as Administrator):
cd src
python SRFT_UDPClient.py test.txt

# Linux/AWS EC2:
cd src
sudo python SRFT_UDPClient.py test.txt

# Run without encryption (Phase 1 mode):
python SRFT_UDPClient.py test.txt --insecure
```

The requested file must exist in the server's `tests/test_files/` folder.
The received file will be saved in the `output/` folder.

### AWS testing with packet loss

```bash
# Apply 3% packet loss on the client EC2 instance:
sudo tc qdisc add dev eth0 root netem loss 3%

# Remove packet loss when done:
sudo tc qdisc del dev eth0 root
```

### Verifying file integrity

```bash
# On Linux, compare MD5 hashes on both machines:
md5sum tests/test_files/   # on server
md5sum output/             # on client
# Both hashes must match for a successful transfer.
```

### Running tests

```bash
# Run all unit tests (108 tests):
cd /path/to/SRFT_UDP_TCP
pytest tests/ -v

# Run specific test modules:
pytest tests/test_crypto.py -v              # Cryptography tests
pytest tests/test_handshake.py -v           # Handshake tests
pytest tests/test_secure_transfer.py -v     # End-to-end security tests
pytest tests/test_replay.py -v              # Replay protection tests

# Run with coverage:
pytest tests/ --cov=src --cov-report=html
```

## Performance Summary

| File size | Packet loss rate | Time     |
| --------- | ---------------- | -------- |
| 100MB     | 0%               | 00:00:10 |
| 100MB     | 2%               | 00:00:15 |
| 100MB     | 3%               | 00:00:17 |
| 100MB     | 4%               | 00:00:22 |


## Performance Summary: Phase 2

| File size | Time     | Server packet sent | Server Retransmission | Client ACK packets |
| --------- | -------- | ------------------ | --------------------- | ------------------ |
| 10 MB     | 00:00:01 | 1281               | 0                     | 81                 |
| 100 MB    | 00:00:14 | 12801              | 0                     | 801                |
| 500 MB    | 00:01:19 | 64001              | 279                   | 4254               |
| 800 MB    | 00:02:03 | 102401             | 224                   | 6608               |
| 1 GB      | 00:02:48 | 131073             | 845                   | 9051               |


## Security tests using 1 mb file

| Test Case                 | Handshake | AEAD Failures  | Replay Drops  | SHA-256 Match  | Result | Time     |
|---------------------------|-----------|----------------|---------------|----------------|--------|----------|
| Secure transfer baseline  | Success   | 0              | 0             | Yes            | Passed | 00:00:00 |
| Wrong PSK                 | Failed    | N/A            | N/A           | N/A            | Passed |
| Tampered packet           | Success   | 1              | 0             | Yes            | Passed |
| Replay attack             | Success   | 0              | 1             | Yes            | Passed |
| Forged packet injection   | Success   | 1              | 0             | Yes            | Passed |


## Security tests using 100 mb file

| Test Case                 | Handshake | AEAD Failures  | Replay Drops  | SHA-256 Match  | Result |   Time   |
|---------------------------|-----------|----------------|---------------|----------------|--------|----------|
| Secure transfer baseline  | Success   | 0              | 0             | Yes            | Passed | 00:00:19 |
| Wrong PSK                 | Failed    | N/A            | N/A           | N/A            | Passed |
| Tampered packet           | Success   | 1              | 0             | Yes            | Passed |
| Replay attack             | Success   | 0              | 1             | Yes            | Passed |
| Forged packet injection   | Success   | 1              | 0             | Yes            | Passed |


## Security tests using 500 mb file

| Test Case                 | Handshake | AEAD Failures  | Replay Drops  | SHA-256 Match  | Result |  Time    |
|---------------------------|-----------|----------------|---------------|----------------|--------|----------|
| Secure transfer baseline  | Success   | 0              | 0             | Yes            | Passed | 00:01:36 |
| Wrong PSK                 | Failed    | N/A            | N/A           | N/A            | Passed | 
| Tampered packet           | Success   | 1              | 0             | Yes            | Passed |
| Replay attack             | Success   | 0              | 1             | Yes            | Passed |
| Forged packet injection   | Success   | 1              | 0             | Yes            | Passed |



## Project structure

```
SRFT_UDP_TCP/
├── README.md
├── config.py                          # Global configuration (ports, window size, PSK, timeouts)
├── src/                               # Main source code
│   ├── __init__.py
│   ├── SRFT_UDPClient.py             # Client entry point
│   ├── SRFT_UDPServer.py             # Server entry point
│   ├── protocol/                      # Packet format and headers
│   │   ├── __init__.py
│   │   ├── packet.py                 # SRFT packet structure
│   │   ├── ip_header.py              # IPv4 header build/parse
│   │   ├── udp_header.py             # UDP header build/parse
│   │   └── checksum.py               # Internet checksum
│   ├── transport/                     # Reliable data transfer
│   │   ├── __init__.py
│   │   ├── raw_socket.py             # Raw socket with encryption/replay detection
│   │   ├── sender.py                 # GBN sender with sliding window
│   │   └── receiver.py               # Cumulative ACK receiver
│   ├── security/                      # Phase 2 security features
│   │   ├── __init__.py
│   │   ├── handshake.py              # ClientHello/ServerHello handshake
│   │   ├── crypto.py                 # AES-GCM AEAD, HKDF, HMAC
│   │   ├── replay.py                 # Sliding-window replay protection
│   │   └── attack.py                 # Attack simulator (tamper/replay/inject)
│   └── utils/                         # Shared utilities
│       ├── __init__.py
│       ├── file_handler.py           # File I/O and chunking
│       └── stats.py                  # Transfer report generation
├── tests/                             # Test suite (108 tests)
│   ├── __init__.py
│   ├── test_checksum.py              # Checksum unit tests
│   ├── test_ip_header.py             # IP header tests
│   ├── test_udp_header.py            # UDP header tests
│   ├── test_crypto.py                # Crypto unit tests
│   ├── test_handshake.py             # Handshake unit tests
│   ├── test_handshake_integration.py # Handshake integration tests
│   ├── test_replay.py                # Replay protection tests
│   ├── test_secure_transfer.py       # End-to-end security tests
│   ├── test_forged_injection.py      # Forged packet tests
│   ├── test_files/                   # Test data (10MB-1GB files)
│   ├── phase1/                       # Phase 1 test reports
│   └── phase2/                       # Phase 2 test reports
├── output/                            # Received files and transfer reports
└── docs/                              # Project documentation
    ├── meeting_notes.md              # Team meeting notes
    ├── project_progress.md           # Implementation progress log
```

---

## Root

| Item          | Description                                                                                                                                                                                                                                                                                               |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **README.md** | This file. Overview of the project, how to run client/server, and a guide to the folder and file structure.                                                                                                                                                                                               |
| **config.py** | Central configuration containing: server/client IP addresses and ports (12345/12346), sliding window size (128 packets), timeout interval (0.5s), maximum retries (10), maximum payload size (8KB), packet flags (SYN, ACK, FIN, DATA), and the pre-shared key (PSK) for Phase 2 cryptographic handshake. |

---

## `src/` — Main source code

| File / folder             | Description                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **src/**init**.py**       | Marks `src` as a Python package.                                                                                                                                                                                                                                                                                                                                                                  |
| **src/SRFT_UDPClient.py** | Client entry point with command-line argument parsing. Performs secure handshake (unless `--insecure`), receives requested file from server, verifies SHA-256 file integrity, and generates client-side transfer report with security statistics (AEAD failures, replay drops).                                                                                                                   |
| **src/SRFT_UDPServer.py** | Server entry point with persistent connection handling. Accepts multiple client requests sequentially, performs secure handshake (unless `--insecure`), sends requested files with SHA-256 hash, supports attack simulation modes (`--attack tamper/replay/inject` for security testing), and generates server-side transfer report. Stays running after each transfer to accept the next client. |

---

## `src/protocol/` — Protocol layer

Defines the SRFT packet format, IP/UDP headers, and checksum calculation for raw socket communication.

| File                       | Description                                                                                                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **protocol/**init**.py**   | Package initializer for the protocol module.                                                                                                                                                                                         |
| **protocol/packet.py**     | SRFT packet structure with sequence number, acknowledgment number, flags (SYN, ACK, FIN, DATA), Internet checksum, and payload. Provides serialization (`to_bytes()`) and deserialization (`from_bytes()`) with checksum validation. |
| **protocol/ip_header.py**  | IPv4 header construction and parsing (20 bytes): version, header length, TTL, protocol (UDP=17), source/destination IP addresses, and IP header checksum.                                                                            |
| **protocol/udp_header.py** | UDP header construction and parsing (8 bytes): source/destination ports, length, and UDP checksum (computed over pseudo-header + UDP header + payload).                                                                              |
| **protocol/checksum.py**   | Internet checksum calculation using one's complement arithmetic with proper overflow handling. Used for both packet-level and IP/UDP header checksums.                                                                               |

---

## `src/transport/` — Transport logic

Implements reliable data transfer over raw UDP with sliding window protocol, retransmission, and integrated security.

| File                        | Description                                                                                                                                                                                                                                                                                 |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **transport/**init**.py**   | Package initializer for the transport module.                                                                                                                                                                                                                                               |
| **transport/raw_socket.py** | Raw socket wrapper providing transparent encryption/decryption and replay detection. Handles SOCK_RAW creation, IP/UDP header construction, and integrates AEAD encryption on send and AEAD decryption + replay detection on receive. Tracks AEAD authentication failures and replay drops. |
| **transport/sender.py**     | Sender implementation using Go-Back-N (GBN) sliding window protocol. Manages send window, timeout-based retransmission, cumulative ACK processing, fast retransmit on 3 duplicate ACKs, and transfer statistics.                                                                            |
| **transport/receiver.py**   | Receiver implementation with cumulative ACK protocol. Handles in-order packet acceptance, duplicate detection, out-of-order packet handling, delayed ACK optimization (ACK every 16 packets or 10ms delay), SHA-256 file hash verification, and statistics tracking.                        |

---

## `src/security/` — Phase 2 security features

Security layer providing handshake, encryption, replay protection, and attack simulation.

| File                      | Description                                                                                                                                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **security/**init**.py**  | Package initializer for the security module.                                                                                                                                                                                                     |
| **security/handshake.py** | ClientHello/ServerHello handshake protocol with HMAC-based verification. Both sides derive session keys from the pre-shared key (PSK) defined in config.py.                                                                                      |
| **security/crypto.py**    | AEAD encryption using AES-GCM for data confidentiality and authenticity. Implements HKDF-SHA256 for key derivation, HMAC for authentication, and AAD (Additional Authenticated Data) construction.                                               |
| **security/replay.py**    | Replay protection using sliding-window bitmap-based detection. Tracks sequence numbers and rejects duplicate or replayed packets.                                                                                                                |
| **security/attack.py**    | Built-in attack simulator for security testing. Implements `--attack tamper` (bit-flip in encrypted payload), `--attack replay` (duplicate packet), and `--attack inject` (forged packet) modes to verify AEAD and replay protection mechanisms. |

---

## `src/utils/` — Shared utilities

| File                      | Description                                                                                                                                                                                                                                                                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **utils/**init**.py**     | Package initializer for the utils module.                                                                                                                                                                                                                                                                                                              |
| **utils/file_handler.py** | File I/O operations: reads files in chunks for transmission (respecting MAX_PAYLOAD_SIZE from config) and writes received chunks to output files sequentially.                                                                                                                                                                                         |
| **utils/stats.py**        | Transfer statistics and report generation. Produces `transfer_report.txt` containing transfer metadata (file name, size, duration, throughput), protocol statistics (packets sent, retransmissions, ACKs, duplicates, out-of-order), and security metrics (handshake status, encryption mode, AEAD failures, replay drops, SHA-256 hash verification). |

---

## `tests/` — Unit tests and test data

Comprehensive test suite covering protocol, security, and integration testing.

| Item                                    | Description                                                                                                                                                                              |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **tests/**init**.py**                   | Package initializer for the tests module.                                                                                                                                                |
| **tests/test_checksum.py**              | Unit tests for checksum calculation: empty data, all zeros, all ones, odd-length data, RFC examples, and bit-flip detection.                                                             |
| **tests/test_ip_header.py**             | Unit tests for IP header build/parse operations with round-trip validation.                                                                                                              |
| **tests/test_udp_header.py**            | Unit tests for UDP header build/parse operations with parametrized test cases.                                                                                                           |
| **tests/test_crypto.py**                | Unit tests for cryptographic operations: HKDF key derivation, HMAC authentication, and AES-GCM AEAD encrypt/decrypt.                                                                     |
| **tests/test_handshake.py**             | Unit tests for ClientHello, ServerHello, and full handshake round-trip with key derivation.                                                                                              |
| **tests/test_handshake_integration.py** | End-to-end handshake integration tests with encrypted data exchange and tamper detection.                                                                                                |
| **tests/test_replay.py**                | Unit tests for replay protection: rejects exact duplicates, in-window duplicates, and packets older than the sliding window.                                                             |
| **tests/test_secure_transfer.py**       | Integration tests for secure file transfer: baseline handshake, encrypted data round-trip, SHA-256 hash verification (match/mismatch), wrong PSK rejection, and tampered data detection. |
| **tests/test_forged_injection.py**      | Tests that forged packets with incorrect encryption keys fail AEAD authentication.                                                                                                       |
| **tests/test_files/**                   | Sample files used for testing transfers (e.g., 10MB, 100MB, 500MB, 800MB, 1GB files).                                                                                                    |
| **tests/phase1/**                       | Phase 1 test reports and screenshots documenting reliable transfer with various file sizes and packet loss scenarios.                                                                    |
| **tests/phase2/**                       | Phase 2 test reports and screenshots documenting secure transfer, attack modes, and AEAD/replay protection validation.                                                                   |

---

## `output/` — Transfer results

| Item                           | Description                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **output/**                    | Directory for received files and transfer reports.                                                                                                                                                                                                                                                                                                                                                                    |
| **output/[filename]**          | Files received by the client are saved here with their original names.                                                                                                                                                                                                                                                                                                                                                |
| **output/transfer_report.txt** | Detailed transfer report generated after each transfer containing: transfer metadata (file name, size, duration, throughput), protocol statistics (packets sent, retransmissions, ACKs sent/received, duplicates, out-of-order packets), and security metrics (handshake status, encryption mode, AEAD authentication failures, replay drops, SHA-256 hash verification result). Generated by both client and server. |

---

## `docs/` — Project documentation

| Item                         | Description                                                                                                                                  |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **docs/meeting_notes.md**    | Team meeting notes documenting project timeline, work distribution, and phase transitions (Phase 1 and Phase 2).                             |
| **docs/project_progress.md** | Comprehensive project progress log with implementation status, module completion tracking, phase summaries, and final deliverable checklist. |

---
