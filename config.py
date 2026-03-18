# SRFT configuration: ports, timeout, window size, PSK (Phase 2)

# config.py
# Central configuration file for the SRFT project.
# Both client and server import from this file.

import os

#Environment variable to specify the server IP address. The IP should be changed manually for testing in different environments. 
# This is the default value for local testing.
SERVER_IP = os.environ.get("SERVER_IP", "127.0.0.1")

SERVER_PORT = 12345
CLIENT_PORT = 12346

IP_PROTOCOL_UDP = 17

MAX_TIMEOUTS = 10

MAX_PAYLOAD_SIZE = 1024


WINDOW_SIZE = 4


TIMEOUT_INTERVAL = 0.5

MAX_RETRIES = 10


FLAG_DATA = 0x01      # This packet carries file data
FLAG_ACK = 0x02       # This packet is an acknowledgment
FLAG_FIN = 0x04       # Sender is done, no more data coming
FLAG_REQ = 0x08       # Client requesting a file (initial request)

