# Phase 2 Security Test Report

Following the instructions of the project, we tested the SRFT security layer (PSK handshake + AEAD encryption + replay protection) on two EC2 instances in the same VPC. All tests were run with 3% simulated packet loss on the client.

```
# Server EC2 (172.31.44.228)
sudo python3 src/SRFT_UDPServer.py 172.31.44.228 ../tests/test_files

# Client EC2 (172.31.43.237)
# 3% packet loss applied
sudo tc qdisc add dev ens5 root netem loss 3%
sudo python3 src/SRFT_UDPClient.py <filename>
```

---

## Test 1 — Secure Transfer (Baseline)

Transferred a small text file and a 10MB binary file with security enabled.

**Expected:** Handshake = Success, AEAD auth failures = 0, Replay drops = 0, SHA-256 match = Yes.

### Test 1a — Small text file (test.txt, 67 bytes)

```
Name of the transferred file: test.txt
Size of the transferred file: 67 bytes
The number of packets sent from the server: 2
The number of retransmitted packets from the server: 0
The number of packets received from the client: 1
The time duration of the file transfer: 00:00:00
Encryption enabled: True
Handshake successful: True
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
```

Client output:
```
SRFT Client: Handshake successful.
SHA-256 file verification: Match
SRFT Client: Replay packets dropped: 0
```

**Result: PASS** — Handshake succeeded, no security errors, SHA-256 match confirmed on client.

### Test 1b — Binary file (test_10mb.bin, 10MB)

```
Name of the transferred file: test_10mb.bin
Size of the transferred file: 10485760 bytes
The number of packets sent from the server: 1281
The number of retransmitted packets from the server: 0
The number of packets received from the client: 79
The time duration of the file transfer: 00:00:01
Encryption enabled: True
Handshake successful: True
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
```

Client output:
```
SRFT Client: Handshake successful.
SHA-256 file verification: Match
SRFT Client: Replay packets dropped: 0
```

**Result: PASS** — 10MB binary transferred in 1 second with encryption, no security errors, SHA-256 match.

---

## Test 2 — Wrong PSK (Authentication Failure)

Changed the client PSK to a different value (`b"WRONGKEYWRONGKEYWRONGKEYWRONGKEY"`) while keeping the server PSK unchanged.

**Expected:** Handshake = Fail, no file output produced.

Client output:
```
SRFT Client: Initiating handshake...
SRFT Client: Handshake timeout, retrying...
SRFT Client: Handshake timeout, retrying...
...
SRFT Client: Handshake failed after 10 retries.
```

Server output:
```
Received ClientHello from 172.31.43.237
Handshake failed: ClientHello HMAC verification failed.
```

**Result: PASS** — Handshake correctly rejected due to PSK mismatch. No file transfer occurred.

---

## Test 3 — Tamper Detection (Integrity)

Used `--attack tamper` on the server to flip 2 bits in the encrypted payload of packet #5.

```
sudo python3 src/SRFT_UDPServer.py 172.31.44.228 ../tests/test_files --attack tamper
```

**Expected:** Receiver drops the tampered packet, transfer completes via retransmission with SHA-256 match.

Server output:
```
Name of the transferred file: test_10mb.bin
Size of the transferred file: 10485760 bytes
The number of packets sent from the server: 1281
The number of retransmitted packets from the server: 32
The number of packets received from the client: 109
The time duration of the file transfer: 00:00:01
Encryption enabled: True
Handshake successful: True
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
```

Client output:
```
Packed was dropped! Corrupted! Checksum verification failed — packet is corrupted
SHA-256 file verification: Match
SRFT Client: Replay packets dropped: 0
```

**Result: PASS** — Tampered packet detected and dropped. Server retransmitted a clean copy. Transfer completed with SHA-256 match.

---

## Test 4 — Replay Protection

Used `--attack replay` on the server to store packet #3 and resend it after packet #8.

```
sudo python3 src/SRFT_UDPServer.py 172.31.44.228 ../tests/test_files --attack replay
```

**Expected:** Replayed packet rejected, Replay drops incremented, SHA-256 match = Yes.

Server output:
```
[ATTACK] Stored packet #3 for replay
[ATTACK] Replayed stored packet after packet #8

Name of the transferred file: test_10mb.bin
Size of the transferred file: 10485760 bytes
The number of packets sent from the server: 1281
The number of retransmitted packets from the server: 0
The number of packets received from the client: 80
The time duration of the file transfer: 00:00:01
Encryption enabled: True
Handshake successful: True
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
```

Client output:
```
Replay detected! Dropping packet with seq_num 2
SHA-256 file verification: Match
SRFT Client: Replay packets dropped: 1
```

**Result: PASS** — Replayed packet detected and dropped. Transfer completed with SHA-256 match.

---

## Test 5 — Forged Injection

Used `--attack inject` on the server to inject a forged packet with random garbage bytes after packet #5.

```
sudo python3 src/SRFT_UDPServer.py 172.31.44.228 ../tests/test_files --attack inject
```

**Expected:** Forged packet rejected, transfer remains correct with SHA-256 match.

Server output:
```
[ATTACK] Injected forged packet after packet #5

Name of the transferred file: test_10mb.bin
Size of the transferred file: 10485760 bytes
The number of packets sent from the server: 1281
The number of retransmitted packets from the server: 0
The number of packets received from the client: 79
The time duration of the file transfer: 00:00:01
Encryption enabled: True
Handshake successful: True
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
```

Client output:
```
Packed was dropped! Corrupted! Checksum verification failed — packet is corrupted
SHA-256 file verification: Match
SRFT Client: Replay packets dropped: 0
```

**Result: PASS** — Forged packet detected and dropped. Transfer completed with SHA-256 match.

---

## Test 6 — MD5 File Integrity Verification

After a successful baseline transfer (Test 1b), compared MD5 hashes on both machines.

```
# Server
md5sum ~/SRFT_UDP_TCP/tests/test_files/test_10mb.bin
b6a2489a23c8e8f40cd9af6245e270e6  test_10mb.bin

# Client
md5sum ~/SRFT_UDP_TCP/output/test_10mb.bin
b6a2489a23c8e8f40cd9af6245e270e6  test_10mb.bin
```

**Result: PASS** — MD5 hashes match. File integrity confirmed.

---

## Summary

| Test | Description | Result |
|------|-------------|--------|
| Test 1a | Secure transfer — text file | **PASS** |
| Test 1b | Secure transfer — 10MB binary | **PASS** |
| Test 2 | Wrong PSK — authentication failure | **PASS** |
| Test 3 | Tamper detection — bit flip in encrypted payload | **PASS** |
| Test 4 | Replay protection — duplicate packet injection | **PASS** |
| Test 5 | Forged injection — random garbage packet | **PASS** |
| Test 6 | MD5 file integrity verification | **PASS** |
