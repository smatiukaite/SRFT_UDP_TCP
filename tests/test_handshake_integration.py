import os
import pytest
from config import PSK, NONCE_SIZE
from security.handshake import (
    build_client_hello,
    parse_client_hello,
    build_server_hello,
    parse_server_hello,
)
from security.crypto import derive_session_keys, encrypt, decrypt, build_aad


class TestHandshakeIntegration:
    """
    Simulates the full handshake + encrypted data exchange
    between client and server without real sockets.
    """

    def test_handshake_then_encrypted_data_exchange(self):
        # === HANDSHAKE ===
        # Client side
        ch_payload, client_nonce = build_client_hello(PSK)

        # Server side
        server_cn = parse_client_hello(PSK, ch_payload)
        sh_payload, server_nonce, session_id = build_server_hello(PSK, server_cn)

        # Client side
        client_sn, client_sid = parse_server_hello(PSK, client_nonce, sh_payload)

        # Both derive keys
        client_keys = derive_session_keys(PSK, client_nonce, client_sn)
        server_keys = derive_session_keys(PSK, server_cn, server_nonce)

        assert client_keys == server_keys
        assert client_sid == session_id

        # === SIMULATED ENCRYPTED DATA TRANSFER ===
        # Server encrypts a data packet
        plaintext = b"This is file chunk #1"
        seq_num, ack_num, flags = 1, 0, 0x01  # FLAG_DATA
        aad = build_aad(session_id, seq_num, ack_num, flags)

        nonce, ciphertext = encrypt(server_keys["enc_key"], plaintext, aad)

        # Client decrypts with its matching key
        client_aad = build_aad(client_sid, seq_num, ack_num, flags)
        recovered = decrypt(client_keys["enc_key"], nonce, ciphertext, client_aad)
        assert recovered == plaintext

    def test_tampered_packet_detected_after_handshake(self):
        # Handshake
        ch_payload, cn = build_client_hello(PSK)
        server_cn = parse_client_hello(PSK, ch_payload)
        sh_payload, sn, sid = build_server_hello(PSK, server_cn)
        client_sn, client_sid = parse_server_hello(PSK, cn, sh_payload)

        keys = derive_session_keys(PSK, cn, client_sn)

        aad = build_aad(sid, 1, 0, 0x01)
        nonce, ct = encrypt(keys["enc_key"], b"secret data", aad)

        # Tamper with ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0xFF
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            decrypt(keys["enc_key"], nonce, bytes(tampered_ct), aad)

    def test_wrong_session_id_in_aad_fails_decrypt(self):
        # Handshake
        ch_payload, cn = build_client_hello(PSK)
        server_cn = parse_client_hello(PSK, ch_payload)
        sh_payload, sn, sid = build_server_hello(PSK, server_cn)
        parse_server_hello(PSK, cn, sh_payload)

        keys = derive_session_keys(PSK, cn, sn)

        aad = build_aad(sid, 0, 0, 0x01)
        nonce, ct = encrypt(keys["enc_key"], b"payload", aad)

        # Attacker uses different session_id
        fake_sid = os.urandom(8)
        bad_aad = build_aad(fake_sid, 0, 0, 0x01)
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            decrypt(keys["enc_key"], nonce, ct, bad_aad)

    def test_wrong_seq_in_aad_fails_decrypt(self):
        ch_payload, cn = build_client_hello(PSK)
        server_cn = parse_client_hello(PSK, ch_payload)
        sh_payload, sn, sid = build_server_hello(PSK, server_cn)
        parse_server_hello(PSK, cn, sh_payload)

        keys = derive_session_keys(PSK, cn, sn)

        aad = build_aad(sid, 5, 0, 0x01)
        nonce, ct = encrypt(keys["enc_key"], b"payload", aad)

        # Attacker replays with different seq_num
        bad_aad = build_aad(sid, 99, 0, 0x01)
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            decrypt(keys["enc_key"], nonce, ct, bad_aad)
