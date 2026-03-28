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

## Current Status (as of Mar 27, 2026)

**Phase 1 progress: Complete**
**Phase 2 progress: ~60% — security modules done, integration remaining**

### Completed Modules

| Module             | File                                  | Contributor    | Summary                                                                                      |
| ------------------ | ------------------------------------- | -------------- | -------------------------------------------------------------------------------------------- |
| Configuration      | `config.py`                           | Kenish, Simona | Server/client ports, window size, timeout, max payload, packet flags, CLIENT_IP/SERVER_IP    |
| Checksum           | `src/protocol/checksum.py`            | Kenish         | Internet checksum calculation and verification with overflow handling                        |
| IP Header          | `src/protocol/ip_header.py`           | Kenish         | Build and parse 20-byte IPv4 headers (version, TTL, protocol, src/dst IP, checksum)          |
| UDP Header         | `src/protocol/udp_header.py`          | Kenish         | Build and parse 8-byte UDP headers (src/dst port, length, checksum)                          |
| SRFT Packet        | `src/protocol/packet.py`              | Kenish         | Packet class with seq#, ack#, flags, checksum, payload; serialization/deserialization        |
| Sender             | `src/transport/sender.py`             | Kenish         | Sliding window protocol with timeout-based retransmission, ACK handling, statistics tracking |
| Raw Socket Wrapper | `src/transport/raw_socket.py`         | Zeyi, Simona   | Reusable RawSocket class extracted from server                                               |
| Server             | `src/SRFT_UDPServer.py`               | Kenish, Zeyi   | Server entry point — refactored to use RawSocket class                                       |
| Client             | `src/SRFT_UDPClient.py`               | Simona         | Client entry point — file request, receive data, send cumulative ACKs                        |
| Receiver           | `src/transport/receiver.py`           | Simona         | Receive buffer with reordering, cumulative ACK generation, duplicate/out-of-order handling   |
| File Handler       | `src/utils/file_handler.py`           | Simona         | File chunking (send) and reassembly (receive)                                                |
| Stats/Report       | `src/utils/stats.py`                  | Simona         | Transfer report output (temporary stats implementation)                                      |
| Crypto             | `src/security/crypto.py`              | Hui            | HKDF-SHA256 key derivation, HMAC, AES-GCM AEAD encrypt/decrypt                               |
| Handshake          | `src/security/handshake.py`           | Zeyi           | ClientHello / ServerHello with HMAC verification, session key derivation                     |
| Replay Protection  | `src/security/replay.py`              | Hui            | Sliding-window replay detection (bitmap-based, configurable window size)                     |
| Checksum Tests     | `tests/test_checksum.py`              | Kenish         | Unit tests (empty data, all zeros, all ones, odd-length, RFC examples, bit-flip detection)   |
| UDP Header Tests   | `tests/test_udp_header.py`            | Zeyi           | Round-trip tests for header build/parse, parametrized                                        |
| IP Header Tests    | `tests/test_ip_header.py`             | Zeyi           | Round-trip tests for IP header build/parse                                                   |
| Crypto Tests       | `tests/test_crypto.py`                | Kenish         | Unit tests for HKDF, HMAC, AES-GCM encrypt/decrypt                                           |
| Handshake Tests    | `tests/test_handshake.py`             | Kenish         | Unit tests for ClientHello, ServerHello, full handshake roundtrip                            |
| Integration Tests  | `tests/test_handshake_integration.py` | Kenish         | End-to-end handshake + encrypted data exchange, tamper detection                             |

### Remaining Work (Not Yet Implemented)

| Module                              | Required For                                                                       |
| ----------------------------------- | ---------------------------------------------------------------------------------- |
| Security integration into data path | Phase 2 — wire handshake, AES-GCM, and replay detection into sender/receiver       |
| SHA-256 file verification           | Phase 2 — end-to-end file digest comparison                                        |
| Built-in attack modes               | Phase 2 — `--attack tamper`, `--attack replay`, `--attack inject` flags            |
| Security test plan                  | Phase 2 — 5 required tests (baseline, wrong PSK, tamper, replay, forged injection) |
| Updated report output               | Phase 2 — add security fields to transfer report                                   |

---

## Phase 1 — Complete

All Phase 1 modules are implemented: client, server, raw socket wrapper, sender, receiver, file handler, and stats. Server refactored to use RawSocket class. Client handles cumulative ACKs and duplicate/out-of-order packets.

## Phase 2 Progress

### Done

1. **Crypto module** — HKDF-SHA256 key derivation, HMAC, AES-GCM AEAD encrypt/decrypt
2. **Handshake module** — ClientHello/ServerHello with HMAC verification, session key derivation
3. **Replay protection module** — Sliding-window bitmap-based detection (configurable window, default 64)
4. **Unit & integration tests** — Crypto, handshake, handshake+crypto integration (87 tests passing)

### Remaining

1. **Security integration into data path** — Wire handshake, AES-GCM encryption, and replay detection into the actual send/receive flow
2. **SHA-256 File Verification** — End-to-end file digest comparison
3. **Built-in Attack Modes** — `--attack tamper`, `--attack replay`, `--attack inject` flags for security testing
4. **Security Test Plan** — 5 required tests (baseline, wrong PSK, tamper, replay, forged injection)
5. **Updated Report Output** — Add security fields (PSK+AEAD enabled, handshake status, AEAD failures, replay drops, SHA-256 match)

---

## Notes

- Server refactored to use modular RawSocket class (no longer inline)
- Security modules are standalone; integration into data path is the next major task
