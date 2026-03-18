# SRFT — Simple Reliable File Transfer

A custom UDP-based file transfer protocol with optional security (Phase 2). This document describes the project layout and the role of each folder and file.

---

## How to run

### Requirements
- Python 3.12+
- Administrator/root privileges (required for raw sockets)
- Both machines must have ports 12345 and 12346 open for UDP traffic

### Configuration
Before running, set the server IP address in `config.py`:
```python
SERVER_IP = "127.0.0.1"  # use 127.0.0.1 for local testing
                          # replace with server EC2 private IP for AWS testing
```

### Starting the server
Run on the server machine with administrator/root privileges:
```bash
# Windows (run PowerShell as Administrator):
cd src
python SRFT_UDPServer.py 127.0.0.1

# Linux/AWS EC2:
cd src
sudo python SRFT_UDPServer.py 
```

### Starting the client
Run on the client machine with administrator/root privileges:
```bash
# Windows (run PowerShell as Administrator):
cd src
python SRFT_UDPClient.py 

# Linux/AWS EC2:
cd src
sudo python SRFT_UDPClient.py 
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

## Project structure

```
SRFT/
├── README.md
├── config.py
├── src/
│   ├── __init__.py
│   ├── SRFT_UDPClient.py
│   ├── SRFT_UDPServer.py
│   ├── protocol/
│   ├── transport/
│   ├── security/
│   └── utils/
├── tests/
│   └── test_files/
├── output/
└── docs/
    └── meeting_notes.md
```


---

## Root

| Item | Description |
|------|-------------|
| **README.md** | This file. Overview of the project, how to run client/server, and a guide to the folder and file structure. |
| **config.py** | Central configuration: server/client ports, timeout values, send/receive window size, and (for Phase 2) the pre-shared key (PSK) or other security parameters. |

---

## `src/` — Main source code

| File / folder | Description |
|---------------|-------------|
| **src/__init__.py** | Marks `src` as a Python package. |
| **src/SRFT_UDPClient.py** | Client entry point. Parses arguments, initiates connection to the server, and drives the file transfer (send or receive) using the protocol and transport layers. |
| **src/SRFT_UDPServer.py** | Server entry point. Listens for client connections, accepts transfer requests, and coordinates sending or receiving files via the protocol and transport layers. |

---

## `src/protocol/` — Application-layer protocol

Defines the SRFT packet format and how headers and checksums are built and parsed.

| File | Description |
|------|-------------|
| **protocol/__init__.py** | Package initializer for the protocol module. |
| **protocol/packet.py** | Application-layer SRFT packet: sequence number, acknowledgment number, flags (e.g. SYN, ACK, FIN, data), checksum, and payload. Build and parse these packets here. |
| **protocol/ip_header.py** | Construction and parsing of the IP header used when sending/receiving raw packets (for custom UDP handling). |
| **protocol/udp_header.py** | Construction and parsing of the UDP header for raw socket usage. |
| **protocol/checksum.py** | Checksum calculation (and verification) for SRFT packets (e.g. over header + payload). |

---

## `src/transport/` — Transport logic

Implements sending and receiving over raw UDP with reliability (windowing, retransmission, ACKs).

| File | Description |
|------|-------------|
| **transport/__init__.py** | Package initializer for the transport module. |
| **transport/raw_socket.py** | Wrapper around the OS raw socket: creating the socket, setting options, and sending/receiving raw IP/UDP frames. Used by sender and receiver. |
| **transport/sender.py** | Sender side: send window management, retransmission on timeout or loss, and timer logic (e.g. per-packet or per-window timeouts). |
| **transport/receiver.py** | Receiver side: receive buffer, reordering of out-of-order segments, and generation of cumulative (or selective) ACKs back to the sender. |

---

## `src/security/` — Phase 2 only

Optional security layer: handshake, encryption, and replay protection.

| File | Description |
|------|-------------|
| **security/__init__.py** | Package initializer for the security module. |
| **security/handshake.py** | ClientHello/ServerHello (or similar) handshake and HMAC-based verification so both sides agree on keys and authenticity (e.g. using the PSK from config). |
| **security/crypto.py** | AEAD encryption (e.g. AES-GCM) for payloads and key derivation (e.g. HKDF) from the handshake/PSK to get encryption and MAC keys. |
| **security/replay.py** | Replay protection: e.g. nonces, sequence numbers, or timestamps to detect and reject replayed packets. |

---

## `src/utils/` — Shared utilities

| File | Description |
|------|-------------|
| **utils/__init__.py** | Package initializer for the utils module. |
| **utils/file_handler.py** | File chunking (splitting a file into SRFT-sized blocks for sending) and reassembly (writing received blocks back to a file in order). |
| **utils/stats.py** | Statistics (bytes sent/received, retransmissions, RTT, etc.) and generation of the final transfer report (e.g. for the `output/` directory). |

---

## `tests/`

| Item | Description |
|------|-------------|
| **tests/** | Directory for test scripts and test data. |
| **tests/test_files/** | Sample files used for testing transfers (e.g. small and large binaries or text files). Add or generate test files here. |

---

## `output/`

| Item | Description |
|------|-------------|
| **output/** | Default destination for files received by the client (or server) and for transfer reports (e.g. from `utils/stats.py`). Received files and report outputs can be written here. |

---

## `docs/`

| Item | Description |
|------|-------------|
| **docs/** | Project documentation. |
| **docs/meeting_notes.md** | Meeting notes, design decisions, and protocol/security discussion. |

---
