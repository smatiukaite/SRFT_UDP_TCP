# ClientHello/ServerHello, HMAC verification

import os
from config import PROTOCOL_VERSION, NONCE_SIZE, SESSION_ID_SIZE, HMAC_SIZE
from security.crypto import compute_hmac, verify_hmac


class HandshakeError(Exception):
    pass


def build_client_hello(psk: bytes) -> tuple[bytes, bytes]:
    """
    Build a ClientHello payload and return the payload and client_nonce.
    """
    client_nonce = os.urandom(NONCE_SIZE)
    mac = compute_hmac(psk, client_nonce + PROTOCOL_VERSION)
    payload = client_nonce + PROTOCOL_VERSION + mac
    return payload, client_nonce


def parse_client_hello(psk: bytes, payload: bytes) -> bytes:
    """
    Parse a ClientHello payload, verify its HMAC, and return the client_nonce.
    """
    expected_len = NONCE_SIZE + len(PROTOCOL_VERSION) + HMAC_SIZE
    if len(payload) != expected_len:
        raise HandshakeError(
            f"Invalid ClientHello length: expected {expected_len}, got {len(payload)}."
        )

    client_nonce = payload[:NONCE_SIZE]
    protocol = payload[NONCE_SIZE : NONCE_SIZE + len(PROTOCOL_VERSION)]
    mac = payload[-HMAC_SIZE:]

    if protocol != PROTOCOL_VERSION:
        raise HandshakeError("Unsupported protocol version.")

    data_to_mac = client_nonce + protocol
    if not verify_hmac(psk, data_to_mac, mac):
        raise HandshakeError("ClientHello HMAC verification failed.")

    return client_nonce


def build_server_hello(psk: bytes, client_nonce: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Build a ServerHello payload and return the payload, server_nonce and session_id.
    """
    server_nonce = os.urandom(NONCE_SIZE)
    session_id = os.urandom(SESSION_ID_SIZE)
    data_to_mac = client_nonce + server_nonce + session_id
    mac = compute_hmac(psk, data_to_mac)
    payload = server_nonce + session_id + mac
    return payload, server_nonce, session_id


def parse_server_hello(psk: bytes, client_nonce: bytes, payload: bytes) -> tuple[bytes, bytes]:
    """
    Parse a ServerHello payload, verify its HMAC against the expected client_nonce,
    and return the server_nonce and session_id.
    """
    expected_len = NONCE_SIZE + SESSION_ID_SIZE + HMAC_SIZE
    if len(payload) != expected_len:
        raise HandshakeError(
            f"Invalid ServerHello length: expected {expected_len}, got {len(payload)}."
        )

    server_nonce = payload[:NONCE_SIZE]
    session_id = payload[NONCE_SIZE : NONCE_SIZE + SESSION_ID_SIZE]
    mac = payload[-HMAC_SIZE:]

    data_to_mac = client_nonce + server_nonce + session_id
    if not verify_hmac(psk, data_to_mac, mac):
        raise HandshakeError("ServerHello HMAC verification failed.")

    return server_nonce, session_id
