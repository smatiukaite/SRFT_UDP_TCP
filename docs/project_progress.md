# SRFT Project Progress Log

## Project Overview

- **Course:** CS 5700 — Fundamentals of Computer Networking (Spring 2026)
- **Project:** Secure Reliable File Transfer (SRFT) over UDP using SOCK_RAW
- **Repo:** https://github.com/KenishRaghu/SRFT_UDP_TCP.git

## Key Deadlines

| Milestone                        | Target Date                  |
| -------------------------------- | ---------------------------- |
| Phase 1 — Reliable File Transfer | Mid-March 2026               |
| Phase 2 — Secure File Transfer   | Mid-April 2026               |
| Final Demo                       | April 21–22, 2026            |
| Final Submission (Canvas)        | April 22, 2026, 11:59 PM PDT |

---

## Current Status (as of Apr 21, 2026)

**Phase 1 progress: Complete**
**Phase 2 progress: Complete — all security features implemented and tested**

### Completed Modules

| Module                 | File                                  | Contributor       | Summary                                                                                                          |
| ---------------------- | ------------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------- |
| Configuration          | `config.py`                           | Kenish, Simona    | Server/client ports, window size, timeout, max payload, packet flags, `--insecure`/`--attack` CLI support        |
| Checksum               | `src/protocol/checksum.py`            | Kenish            | Internet checksum calculation and verification with overflow handling                                            |
| IP Header              | `src/protocol/ip_header.py`           | Kenish            | Build and parse 20-byte IPv4 headers (version, TTL, protocol, src/dst IP, checksum)                              |
| UDP Header             | `src/protocol/udp_header.py`          | Kenish            | Build and parse 8-byte UDP headers (src/dst port, length, checksum)                                              |
| SRFT Packet            | `src/protocol/packet.py`              | Kenish            | Packet class with seq#, ack#, flags, checksum, payload; serialization/deserialization                            |
| Sender                 | `src/transport/sender.py`             | Kenish            | Sliding window protocol with timeout-based retransmission, ACK handling, statistics tracking                     |
| Raw Socket Wrapper     | `src/transport/raw_socket.py`         | Zeyi, Simona, Hui | RawSocket class with AEAD encryption/decryption and replay detection in receive path                             |
| Server                 | `src/SRFT_UDPServer.py`               | Kenish, Zeyi, Hui | Server entry point — handshake, SHA-256 hash in FIN, attack mode support, server stays running between transfers |
| Client                 | `src/SRFT_UDPClient.py`               | Simona            | Client entry point — `--insecure` flag, SHA-256 verification reporting, replay stats                             |
| Receiver               | `src/transport/receiver.py`           | Simona, Hui       | Cumulative ACK with delayed ACK optimization, SHA-256 hash computation + FIN verification                        |
| File Handler           | `src/utils/file_handler.py`           | Simona            | File chunking (send) and reassembly (receive)                                                                    |
| Stats/Report           | `src/utils/stats.py`                  | Simona, Hui       | Transfer report with security fields: handshake, encryption, AEAD failures, replay drops, SHA-256 match          |
| Crypto                 | `src/security/crypto.py`              | Hui               | HKDF-SHA256 key derivation, HMAC, AES-GCM AEAD encrypt/decrypt                                                   |
| Handshake              | `src/security/handshake.py`           | Zeyi              | ClientHello / ServerHello with HMAC verification, session key derivation                                         |
| Replay Protection      | `src/security/replay.py`              | Hui               | Sliding-window replay detection (bitmap-based, configurable window size)                                         |
| Attack Interceptor     | `src/security/attack.py`              | Kenish, Simona    | `AttackInterceptor` for `--attack tamper`, `--attack replay`, `--attack inject` modes                            |
| Checksum Tests         | `tests/test_checksum.py`              | Kenish            | Unit tests (empty data, all zeros, all ones, odd-length, RFC examples, bit-flip detection)                       |
| UDP Header Tests       | `tests/test_udp_header.py`            | Zeyi              | Round-trip tests for header build/parse, parametrized                                                            |
| IP Header Tests        | `tests/test_ip_header.py`             | Zeyi              | Round-trip tests for IP header build/parse                                                                       |
| Crypto Tests           | `tests/test_crypto.py`                | Kenish            | Unit tests for HKDF, HMAC, AES-GCM encrypt/decrypt                                                               |
| Handshake Tests        | `tests/test_handshake.py`             | Kenish            | Unit tests for ClientHello, ServerHello, full handshake roundtrip                                                |
| Integration Tests      | `tests/test_handshake_integration.py` | Kenish            | End-to-end handshake + encrypted data exchange, tamper detection                                                 |
| Replay Tests           | `tests/test_replay.py`                | Simona            | Reject exact duplicate, reject in-window duplicate, reject packet older than window                              |
| Secure Transfer Tests  | `tests/test_secure_transfer.py`       | Simona            | Baseline handshake, data roundtrip, SHA-256 match/mismatch, wrong PSK, tampered data                             |
| Forged Injection Tests | `tests/test_forged_injection.py`      | Simona            | Forged packet with wrong key fails AEAD authentication                                                           |
| Phase 1 Test Report    | `tests/phase1/report.md`              | Simona, Kenish    | Phase 1 test screenshots and report (10MB, 100MB, 500MB, 800MB, 1GB, md5sum)                                     |

### Project Completion Summary

✅ **All core implementation complete**

- Phase 1: Reliable file transfer over UDP with SOCK_RAW
- Phase 2: Secure file transfer with encryption, authentication, and attack protection

✅ **Ready for final demo and submission**

- Demo dates: April 22, 2026
- Final submission: April 22, 2026, 11:59 PM PDT

---

## Phase 1 — Complete

All Phase 1 modules are implemented: client, server, raw socket wrapper, sender, receiver, file handler, and stats. Server refactored to use RawSocket class. Client handles cumulative ACKs and duplicate/out-of-order packets. Performance improvements: delayed ACK optimization (ACK every 16 packets or after 10ms delay). Tested with files up to 1GB with md5sum verification.

## Phase 2 — Complete ✅

### Completed Features

1. **Crypto module** — HKDF-SHA256 key derivation, HMAC, AES-GCM AEAD encrypt/decrypt (`e3f0efc`)
2. **Handshake module** — ClientHello/ServerHello with HMAC verification (`57d37f0`)
3. **Replay protection module** — Sliding-window bitmap-based detection (`6971bdb`)
4. **AEAD integration into data path** — Encryption/decryption wired into RawSocket send/receive (`28eee39`)
5. **Replay detection integration** — Wired into RawSocket receive path, drops replayed packets (`632b527`)
6. **SHA-256 file verification** — Server hashes file, sends digest in FIN; receiver verifies on arrival (`632b527`)
7. **Updated report output** — Handshake status, encryption, AEAD failures, replay drops, SHA-256 match (`632b527`, `dfe5338`)
8. **Built-in attack modes** — `AttackInterceptor` with `--attack tamper/replay/inject` flags (`ad97482`)
9. **`--insecure` flag** — Client and server can run without encryption for testing (`ad97482`)
10. **Server persistence** — Server stays running after transfer, accepts next request (`a900552`)
11. **Performance improvements** — Delayed ACK (every 16 packets or 10ms), reduced print noise (`1835b66`, `ee24c13`)
12. **Phase 2 tests** — Replay detection, secure transfer (SHA-256, wrong PSK, tamper), forged injection — 108 tests passing (`38d41e0`)
13. **Enhanced transfer reporting** — Client-side transfer statistics with AEAD/replay counts (`31cd2cd`)
14. **AEAD authentication failure reporting** — Client prints detailed AEAD authentication failures (`e3e79ea`)
15. **Attack.py AEAD integration** — Modified tamper and inject modes to trigger AEAD authentication instead of basic checksum (`1f7ef87`)
16. **Comprehensive security metrics** — Wired client AEAD/replay counts back to server's transfer_report.txt (`d1c4c4b`)

### Final Status

**All Phase 2 security features are fully implemented, integrated, and tested:**

- ✅ End-to-end encryption with AES-GCM AEAD
- ✅ Secure handshake with HMAC-based key exchange
- ✅ Replay attack protection with sliding-window detection
- ✅ File integrity verification with SHA-256
- ✅ Attack detection and reporting (tamper, replay, inject)
- ✅ Comprehensive security statistics and transfer reports
- ✅ Complete test suite with 108 passing tests

**Project ready for final demo (April 22, 2026) and submission (April 22, 2026)**
