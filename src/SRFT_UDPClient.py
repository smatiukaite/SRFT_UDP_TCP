# Client entry point

# Main client program for Secure Reliable File Transfer.
# The client sends a file name request to the server, then sends the file

# Note: This code was written based on the book "Computer Networking: A Top-Down Approach" by Kurose and Ross, specifically chapter 3.4 
# 'Principles of Reliable Data Transfer', on reliable data transfer protocols (pipelined sliding window protocol). We are using 
# Go-Back-N (GBN) approach.

import socket
import threading
import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SERVER_PORT, CLIENT_PORT, MAX_PAYLOAD_SIZE, FLAG_DATA, FLAG_FIN, FLAG_ACK, FLAG_REQ
from protocol.ip_header import build_ip_header, parse_ip_header
from protocol.udp_header import build_udp_header, parse_udp_header
from protocol.packet import Packet, HEADER_SIZE
from transport.receiver import Receiver
from utils.file_handler import write_file_chunks
from utils.stats import Stats

class SRFTClient:
    """
    The main client class.
    
    Flow:
    1. Create raw socket and send file request to server
    2. Server sends file in chunks using our reliable protocol over raw UDP sockets
    3. Client receives chunks, sends ACKs, and reorders as needed
    4. When done, client sends final ACK and outputs statistics
    """