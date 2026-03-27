import os
import pytest
from config import PSK, NONCE_SIZE, SESSION_ID_SIZE, HMAC_SIZE, PROTOCOL_VERSION
from security.handshake import (
    build_client_hello,
    parse_client_hello,
    build_server_hello,
    parse_server_hello,
    HandshakeError,
)
from security.crypto import compute_hmac


class TestClientHello:
    """Tests for building and parsing ClientHello."""

    def test_build_payload_length(self):
        payload, nonce = build_client_hello(PSK)
        expected = NONCE_SIZE + len(PROTOCOL_VERSION) + HMAC_SIZE
        assert len(payload) == expected

    def test_build_nonce_length(self):
        _, nonce = build_client_hello(PSK)
        assert len(nonce) == NONCE_SIZE

    def test_build_nonce_is_random(self):
        _, n1 = build_client_hello(PSK)
        _, n2 = build_client_hello(PSK)
        assert n1 != n2

    def test_parse_returns_correct_nonce(self):
        payload, expected_nonce = build_client_hello(PSK)
        parsed_nonce = parse_client_hello(PSK, payload)
        assert parsed_nonce == expected_nonce

    def test_parse_rejects_wrong_psk(self):
        payload, _ = build_client_hello(PSK)
        wrong_psk = b"X" * 32
        with pytest.raises(HandshakeError, match="HMAC verification failed"):
            parse_client_hello(wrong_psk, payload)

    def test_parse_rejects_truncated_payload(self):
        payload, _ = build_client_hello(PSK)
        with pytest.raises(HandshakeError, match="Invalid ClientHello length"):
            parse_client_hello(PSK, payload[:-1])

    def test_parse_rejects_extended_payload(self):
        payload, _ = build_client_hello(PSK)
        with pytest.raises(HandshakeError, match="Invalid ClientHello length"):
            parse_client_hello(PSK, payload + b"\x00")

    def test_parse_rejects_tampered_nonce(self):
        payload, _ = build_client_hello(PSK)
        tampered = bytearray(payload)
        tampered[0] ^= 0xFF  # flip a nonce byte
        with pytest.raises(HandshakeError, match="HMAC verification failed"):
            parse_client_hello(PSK, bytes(tampered))

    def test_parse_rejects_tampered_protocol_version(self):
        payload, _ = build_client_hello(PSK)
        tampered = bytearray(payload)
        tampered[NONCE_SIZE] ^= 0xFF  # flip first byte of protocol version
        with pytest.raises(HandshakeError, match="protocol version"):
            parse_client_hello(PSK, bytes(tampered))

    def test_parse_rejects_tampered_hmac(self):
        payload, _ = build_client_hello(PSK)
        tampered = bytearray(payload)
        tampered[-1] ^= 0xFF  # flip last byte of HMAC
        with pytest.raises(HandshakeError, match="HMAC verification failed"):
            parse_client_hello(PSK, bytes(tampered))


class TestServerHello:
    """Tests for building and parsing ServerHello."""

    def setup_method(self):
        self.client_nonce = os.urandom(NONCE_SIZE)

    def test_build_payload_length(self):
        payload, _, _ = build_server_hello(PSK, self.client_nonce)
        expected = NONCE_SIZE + SESSION_ID_SIZE + HMAC_SIZE
        assert len(payload) == expected

    def test_build_returns_correct_length_nonce_and_session_id(self):
        _, server_nonce, session_id = build_server_hello(PSK, self.client_nonce)
        assert len(server_nonce) == NONCE_SIZE
        assert len(session_id) == SESSION_ID_SIZE

    def test_build_nonce_is_random(self):
        _, n1, _ = build_server_hello(PSK, self.client_nonce)
        _, n2, _ = build_server_hello(PSK, self.client_nonce)
        assert n1 != n2

    def test_parse_returns_correct_values(self):
        payload, expected_nonce, expected_sid = build_server_hello(PSK, self.client_nonce)
        server_nonce, session_id = parse_server_hello(PSK, self.client_nonce, payload)
        assert server_nonce == expected_nonce
        assert session_id == expected_sid

    def test_parse_rejects_wrong_psk(self):
        payload, _, _ = build_server_hello(PSK, self.client_nonce)
        with pytest.raises(HandshakeError, match="HMAC verification failed"):
            parse_server_hello(b"X" * 32, self.client_nonce, payload)

    def test_parse_rejects_wrong_client_nonce(self):
        payload, _, _ = build_server_hello(PSK, self.client_nonce)
        wrong_cn = os.urandom(NONCE_SIZE)
        with pytest.raises(HandshakeError, match="HMAC verification failed"):
            parse_server_hello(PSK, wrong_cn, payload)

    def test_parse_rejects_truncated_payload(self):
        payload, _, _ = build_server_hello(PSK, self.client_nonce)
        with pytest.raises(HandshakeError, match="Invalid ServerHello length"):
            parse_server_hello(PSK, self.client_nonce, payload[:-1])

    def test_parse_rejects_tampered_server_nonce(self):
        payload, _, _ = build_server_hello(PSK, self.client_nonce)
        tampered = bytearray(payload)
        tampered[0] ^= 0xFF
        with pytest.raises(HandshakeError, match="HMAC verification failed"):
            parse_server_hello(PSK, self.client_nonce, bytes(tampered))

    def test_parse_rejects_tampered_session_id(self):
        payload, _, _ = build_server_hello(PSK, self.client_nonce)
        tampered = bytearray(payload)
        tampered[NONCE_SIZE] ^= 0xFF  # flip first byte of session_id
        with pytest.raises(HandshakeError, match="HMAC verification failed"):
            parse_server_hello(PSK, self.client_nonce, bytes(tampered))

    def test_parse_rejects_empty_payload(self):
        with pytest.raises(HandshakeError, match="Invalid ServerHello length"):
            parse_server_hello(PSK, self.client_nonce, b"")


class TestHandshakeRoundtrip:
    """End-to-end handshake flow without sockets."""

    def test_full_handshake_flow(self):
        # Client builds hello
        ch_payload, client_nonce = build_client_hello(PSK)

        # Server parses and responds
        parsed_cn = parse_client_hello(PSK, ch_payload)
        assert parsed_cn == client_nonce

        sh_payload, server_nonce, session_id = build_server_hello(PSK, parsed_cn)

        # Client parses server hello
        parsed_sn, parsed_sid = parse_server_hello(PSK, client_nonce, sh_payload)
        assert parsed_sn == server_nonce
        assert parsed_sid == session_id

    def test_derived_keys_match_both_sides(self):
        from security.crypto import derive_session_keys

        ch_payload, client_nonce = build_client_hello(PSK)
        parsed_cn = parse_client_hello(PSK, ch_payload)
        sh_payload, server_nonce, _ = build_server_hello(PSK, parsed_cn)
        parsed_sn, _ = parse_server_hello(PSK, client_nonce, sh_payload)

        # Both sides derive keys from same inputs
        client_keys = derive_session_keys(PSK, client_nonce, parsed_sn)
        server_keys = derive_session_keys(PSK, parsed_cn, server_nonce)
        assert client_keys == server_keys
