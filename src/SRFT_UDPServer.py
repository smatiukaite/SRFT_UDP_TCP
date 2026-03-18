# Server entry point

# Main server program for Secure Reliable File Transfer.
# The server waits for a file request from the client, then sends the file
# using our reliable protocol over raw UDP sockets.

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
from transport.sender import Sender
from utils.file_handler import FileHandler
from utils.stats import Stats


class SRFTServer:
    """
    The main server class.
    
    Flow:
    1. Create raw socket and wait for client request
    2. Client sends filename it wants
    3. Server reads file, splits into chunks
    4. Server sends chunks using Sender (reliable, windowed)
    5. Server listens for ACKs and updates Sender
    6. When done, send FIN and wait for final ACK
    7. Output statistics
    """
    
    def __init__(self, server_ip: str, files_directory: str = './test_files'):
        """
        Initialize the server.
        
        Args:
            server_ip: This server's IP address
            files_directory: Where to look for files that clients request
        """
        self.server_ip = server_ip
        self.files_directory = files_directory
        
        self.client_ip = None
        
       
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except PermissionError:
            print("ERROR: Raw sockets require root privileges. Run with sudo.")
            sys.exit(1)
        
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        self.socket.bind((self.server_ip, SERVER_PORT))
        
        self.stats = Stats()
        
        self.sender = None
        
        self.running = True
    
    def _send_raw_packet(self, packet: Packet):
        """
        Send a Packet object over the raw socket.
        
        This builds the IP header, UDP header, and combines with our
        app-layer packet, then sends the whole thing.
        
        Args:
            packet: Our Packet object to send
        """
        app_data = packet.to_bytes()
        
        
        udp_header = build_udp_header(SERVER_PORT, CLIENT_PORT, len(app_data))
        
        
        ip_payload_length = len(udp_header) + len(app_data)
        ip_header = build_ip_header(self.server_ip, self.client_ip, ip_payload_length)
        
        raw_packet = ip_header + udp_header + app_data
        
        self.socket.sendto(raw_packet, (self.client_ip, CLIENT_PORT))
    
    def _receive_packet(self) -> tuple:
        """
        Receive and parse a packet from the socket.
        
        Returns:
            Tuple of (Packet object, source_ip) or (None, None) if invalid
        """
        try:
            raw_data, addr = self.socket.recvfrom(65535)
            
            ip_info = parse_ip_header(raw_data)
            
            if ip_info['protocol'] != 17:
                return None, None
            
            ip_header_len = ip_info['header_length']
            udp_info = parse_udp_header(raw_data[ip_header_len:])
            
            if udp_info['dst_port'] != SERVER_PORT:
                return None, None
            
            app_data_start = ip_header_len + 8  # 8 = UDP header size
            app_data = raw_data[app_data_start:]
            
            try:
                packet = Packet.from_bytes(app_data)
                return packet, ip_info['src_ip']
            except ValueError as e:
                print(f"Corrupted packet received: {e}")
                return None, None
                
        except socket.timeout:
            return None, None
    
    def _ack_listener(self):
        """
        Background thread that listens for ACKs from the client.
        
        When we receive an ACK, we pass it to the Sender so it can
        update its window and stop retransmitting acknowledged packets.
        """
        while self.running:
            packet, src_ip = self._receive_packet()
            
            if packet is None:
                continue
            
            if packet.is_ack():
                self.sender.handle_ack(packet.ack_num)
                self.stats.packets_received += 1
    
    def _send_file(self, filename: str):
        """
        Send a file to the client.
        
        Reads the file, splits into chunks, and sends each chunk
        as a DATA packet using the Sender for reliability.
        
        Args:
            filename: Name of the file to send
        """
        filepath = os.path.join(self.files_directory, filename)
        
        if not os.path.exists(filepath):
            print(f"ERROR: File not found: {filepath}")
            return
        
        file_size = os.path.getsize(filepath)
        self.stats.file_name = filename
        self.stats.file_size = file_size
        
        print(f"Sending file: {filename} ({file_size} bytes)")
        
        self.sender = Sender(self._send_raw_packet)
        
        ack_thread = threading.Thread(target=self._ack_listener, daemon=True)
        ack_thread.start()
        
        self.stats.start_time = time.time()
        
        file_handler = FileHandler()
        file_handler.open_input_file(filepath)
        for chunk in file_handler.read_file_chunks(MAX_PAYLOAD_SIZE):
            self.sender.send_packet(chunk, FLAG_DATA)
        file_handler.close_input_file()
        
        self.sender.send_packet(b'', FLAG_FIN)
        
        print("Waiting for all ACKs...")
        if self.sender.wait_for_completion(timeout=60.0):
            print("All packets acknowledged!")
        else:
            print("WARNING: Timed out waiting for ACKs")
        
        self.stats.end_time = time.time()
        
        sender_stats = self.sender.get_stats()
        self.stats.packets_sent = sender_stats['packets_sent']
        self.stats.retransmissions = sender_stats['retransmissions']
        
        self.running = False
        self.sender.stop()
    
    def start(self):
        """
        Start the server and wait for a client request.
        
        This is the main entry point. It waits for a REQ packet
        containing a filename, then sends that file.
        """
        print(f"Server listening on {self.server_ip}:{SERVER_PORT}")
        print("Waiting for file request...")
        
        while True:
            packet, src_ip = self._receive_packet()
            
            if packet is None:
                continue
            
            if packet.is_request():
                self.client_ip = src_ip
                filename = packet.payload.decode('utf-8')
                print(f"Received request for '{filename}' from {src_ip}")
                
                self._send_file(filename)
                
                self.stats.write_report()
                break
        
        self.socket.close()
        print("Server finished.")


def main():
    """
    Entry point for the server program.
    
    Usage: sudo python SRFT_UDPServer.py <server_ip> [files_directory]
    """
    if len(sys.argv) < 2:
        print("Usage: sudo python SRFT_UDPServer.py <server_ip> [files_directory]")
        print("Example: sudo python SRFT_UDPServer.py 192.168.1.100 ./test_files")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    files_dir = sys.argv[2] if len(sys.argv) > 2 else './test_files'
    
    server = SRFTServer(server_ip, files_dir)
    server.start()


if __name__ == '__main__':
    main()