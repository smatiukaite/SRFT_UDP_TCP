import os
import pytest
from cryptography.exceptions import InvalidTag
from security.handshake import build_client_hello, parse_client_hello, build_server_hello, parse_server_hello
from config import PSK
from security.crypto import derive_session_keys, build_aad, encrypt, decrypt

class TestForgedInjection:
    def do_handshake(self):
        ch_payload, client_nonce = build_client_hello(PSK)
        server_client_nonce = parse_client_hello(PSK, ch_payload)
        sh_payload, server_nonce, session_id = build_server_hello(PSK, server_client_nonce)
        parse_server_hello(PSK, client_nonce, sh_payload)

        client_keys = derive_session_keys(PSK, client_nonce, server_nonce)
        server_keys = derive_session_keys(PSK, server_client_nonce, server_nonce)
        return {
            "client_keys": client_keys,
            "server_keys": server_keys,
            "session_id": session_id,
        }

    def test_random_nonce_and_random_ciphertext_are_rejected(self):
        result = self.do_handshake()
        session_id = result["session_id"]
        fake_nonce = os.urandom(12)
        fake_ciphertext = os.urandom(64)
        aad = build_aad(session_id, 2, 0, 0x01)

        with pytest.raises(InvalidTag):
            decrypt(result["client_keys"]["enc_key"], fake_nonce, fake_ciphertext, aad)

    def test_random_ciphertext_is_rejected(self):
        result = self.do_handshake()
        session_id = result["session_id"]
        fake_nonce = os.urandom(12)
        fake_ciphertext = os.urandom(32)
        aad = build_aad(session_id, 1, 0, 0x01)

        with pytest.raises(InvalidTag):
            decrypt(result["client_keys"]["enc_key"], fake_nonce, fake_ciphertext, aad)

    def test_ciphertext_from_different_key_is_rejected(self):
        result = self.do_handshake()
        session_id = result["session_id"]
        aad = build_aad(session_id, 3, 0, 0x01)
        attacker_key = os.urandom(32)
        nonce, attacker_ciphertext = encrypt(attacker_key, b"authentic payload", aad)

        with pytest.raises(InvalidTag):
            decrypt(result["client_keys"]["enc_key"], nonce, attacker_ciphertext, aad)

    def test_ciphertext_bound_to_different_session_id_is_rejected(self):
        result = self.do_handshake()
        session_id = result["session_id"]
        good_aad = build_aad(session_id, 4, 0, 0x01)
        nonce, ciphertext = encrypt(result["server_keys"]["enc_key"], b"valid payload", good_aad)
        fake_session_id = os.urandom(8)
        
        #Attacker forges packet metadata by changing flags in the AAD
        bad_aad = build_aad(fake_session_id, 4, 0, 0x01)
        with pytest.raises(InvalidTag):
            decrypt(result["client_keys"]["enc_key"], nonce, ciphertext, bad_aad)

    def test_ciphertext_bound_to_different_sequence_number_is_rejected(self):
        result = self.do_handshake()
        session_id = result["session_id"]
        aad = build_aad(session_id, 5, 0, 0x01)
        nonce, ciphertext = encrypt(result["server_keys"]["enc_key"], b"valid payload", aad)

        #Attacker forges packet metadata by changing flags in the AAD
        bad_aad = build_aad(session_id, 99, 0, 0x01)
        with pytest.raises(InvalidTag):
            decrypt(result["client_keys"]["enc_key"], nonce, ciphertext, bad_aad)

    def test_ciphertext_bound_to_different_flags_is_rejected(self):
        result = self.do_handshake()
        session_id = result["session_id"]
        aad = build_aad(session_id, 6, 0, 0x01)
        nonce, ciphertext = encrypt(result["server_keys"]["enc_key"], b"valid payload", aad)

        #Attacker forges packet metadata by changing flags in the AAD
        bad_aad = build_aad(session_id, 6, 0, 0x02)
        with pytest.raises(InvalidTag):
            decrypt(result["client_keys"]["enc_key"], nonce, ciphertext, bad_aad)