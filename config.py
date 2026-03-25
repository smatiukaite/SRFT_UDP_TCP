# Central configuration file for the SRFT project.
# Both client and server import from this file.

import os

PROTOCOL_VERSION = b"SRFT 1.0"

# Environment variable to specify the server IP address. The IP should be changed manually for testing in different environments.
# This is the default value for local testing.
SERVER_IP = os.environ.get("SERVER_IP", "127.0.0.1")
CLIENT_IP = os.environ.get("CLIENT_IP", "127.0.0.1")

SERVER_PORT = 12345
CLIENT_PORT = 12346

MAX_TIMEOUTS = 10

MAX_PAYLOAD_SIZE = 1024


WINDOW_SIZE = 4


TIMEOUT_INTERVAL = 0.5

MAX_RETRIES = 10


FLAG_DATA = 0x01  # This packet carries file data
FLAG_ACK = 0x02  # This packet is an acknowledgment
FLAG_FIN = 0x04  # Sender is done, no more data coming
FLAG_REQ = 0x08  # Client requesting a file (initial request)
FLAG_CLIENT_HELLO = 0x10  # Client Hello
FLAG_SERVER_HELLO = 0x20  # Server Hello

# Security parameters
PSK = b"M2sWxogShvHPigFrMxOZP8rD7KnEvKBd"  # Pre-shared key for security

NONCE_SIZE = 16 # Size of nonces used in the handshake
SESSION_ID_SIZE = 8 # Size of session IDs used in the handshake
HMAC_SIZE = 32 # Size of HMACs (for HMAC-SHA256)
