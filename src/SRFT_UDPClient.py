# Client entry point

# Main client program for Secure Reliable File Transfer.
# The client sends a file name request to the server, then sends the file

# Note: This code was written based on the book "Computer Networking: A Top-Down Approach" by Kurose and Ross, specifically chapter 3.4 
# 'Principles of Reliable Data Transfer', on reliable data transfer protocols (pipelined sliding window protocol). We are using Go-Back-N (GBN) approach.

#SRFT_UDPClient takes a filename as input and sends that filename to the server to request the download,

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SERVER_PORT, CLIENT_PORT, MAX_PAYLOAD_SIZE, FLAG_DATA, FLAG_FIN, FLAG_ACK, FLAG_REQ
from protocol.ip_header import build_ip_header, parse_ip_header
from protocol.udp_header import build_udp_header, parse_udp_header
from protocol.packet import Packet, HEADER_SIZE
from transport.receiver import Receiver
class SRFTClient:
    """
    The main client class.
    
    Flow:
    1. Create raw socket and send file request to server
    2. Server sends file in chunks using our reliable protocol over raw UDP sockets
    3. Client receives chunks, sends ACKs, and reorders as needed
    4. When done, client sends final ACK and outputs statistics
    """

"""
SRFT_UDPClient.py
Owns:
arguments
setup
send filename request
start receiving
shutdown / final user output

For Phase 1, I would expect this file to include these tasks:
parse command-line arguments
validate filename / destination inputs
create client raw socket bound to client IP/port
create receiver with output target
create and send request packet with FLAG_REQ
run receive loop until FIN/transfer complete
close receiver/file/socket cleanly
print final result to user
optionally expose md5 / saved-file information for verification
That is enough for a solid client entry point.
"""