# Server entry point

# Main server program for Secure Reliable File Transfer.
# The server waits for a file request from the client, then sends the file
# using our reliable protocol over raw UDP sockets.

import hashlib
import threading
import time
import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SERVER_IP, SERVER_PORT, CLIENT_PORT, MAX_PAYLOAD_SIZE, FLAG_DATA, FLAG_FIN, FLAG_ACK, FLAG_REQ, PSK, FLAG_SERVER_HELLO
from protocol.packet import Packet, HEADER_SIZE
from transport.sender import Sender
from transport.raw_socket import RawSocket
from utils.file_handler import FileHandler
from utils.stats import Stats
from security.handshake import parse_client_hello, build_server_hello
from security.crypto import derive_session_keys
from security.attack import AttackInterceptor


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
    
    def __init__(self, server_ip: str, files_directory: str = './test_files', secure: bool = True, attack_mode: str = None):
        """
        Initialize the server.
        
        Args:
            server_ip: This server's IP address
            files_directory: Where to look for files that clients request
            secure: Whether to use encryption and handshake
        """
        self.server_ip = server_ip
        self.files_directory = files_directory
        self.secure = secure
        
        self.client_ip = None
        
        self.raw_sock = RawSocket(self.server_ip, SERVER_PORT)
        
        self.stats = Stats()
        
        self.sender = None
        self.session_keys = None
        self.session_id = None
        
        self.running = True
        self.attack_mode = attack_mode
    
    def _send_raw_packet(self, packet: Packet):
        """
        Send a Packet object over the raw socket.
        """
        self.raw_sock.send_packet(packet, self.server_ip, SERVER_PORT, self.client_ip, CLIENT_PORT)
    
    def _receive_packet(self) -> tuple:
        """
        Receive and parse a packet from the socket.
        
        Returns:
            Tuple of (Packet object, source_ip) or (None, None) if invalid
        """
        packet, src_ip, _ = self.raw_sock.receive_packet()
        return packet, src_ip
    
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
        
        if self.attack_mode:
            interceptor = AttackInterceptor(
                self.raw_sock, self.server_ip, SERVER_PORT,
                self.client_ip, CLIENT_PORT, self.attack_mode
            )
            self.sender = Sender(interceptor.send)
            print(f"[ATTACK MODE: {self.attack_mode}] Attack will be applied during transfer.")
        else:
            self.sender = Sender(self._send_raw_packet)
        self.running = True
        
        ack_thread = threading.Thread(target=self._ack_listener, daemon=True)
        ack_thread.start()
        
        self.stats.start_time = time.time()
        
        sha256 = hashlib.sha256()
        file_handler = FileHandler()
        file_handler.open_input_file(filepath)
        for chunk in file_handler.read_file_chunks(MAX_PAYLOAD_SIZE):
            sha256.update(chunk)
            self.sender.send_packet(chunk, FLAG_DATA)
        file_handler.close_input_file()

        self.sender.send_packet(sha256.digest(), FLAG_FIN)
        
        print("Waiting for all ACKs...")
        if self.sender.wait_for_completion(timeout=60.0):
            print("All packets acknowledged!")
        else:
            print("WARNING: Timed out waiting for ACKs")
        
        self.stats.end_time = time.time()
        
        sender_stats = self.sender.get_stats()
        self.stats.packets_sent = sender_stats['packets_sent']
        self.stats.retransmissions = sender_stats['retransmissions']
        self.stats.handshake_success = self.session_keys is not None
        self.stats.encryption_enabled = self.secure
        self.stats.aead_failures = self.raw_sock.aead_failures
        self.stats.replay_drops = self.raw_sock.replay_drops

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

            if packet.is_hello_client():
                if not self.secure:
                    print(f"Ignored ClientHello from {src_ip}: Server is running in insecure mode.")
                    continue
                try:
                    print(f"Received ClientHello from {src_ip}")
                    self.client_ip = src_ip
                    client_nonce = parse_client_hello(PSK, packet.payload)
                    payload, server_nonce, session_id = build_server_hello(PSK, client_nonce)
                    self.session_keys = derive_session_keys(PSK, client_nonce, server_nonce)
                    self.session_id = session_id
                    # Send ServerHello
                    hello_packet = Packet(seq_num=0, ack_num=0, flags=FLAG_SERVER_HELLO, payload=payload)
                    self.raw_sock.send_packet(hello_packet, self.server_ip, SERVER_PORT, self.client_ip, CLIENT_PORT)
                    print("Sent ServerHello, handshake complete.")
                    self.raw_sock.enable_crypto(self.session_keys, self.session_id)
                except Exception as e:
                    print(f"Handshake failed: {e}")
                continue

            if packet.is_request():
                if self.secure and self.session_keys is None:
                    print(f"Ignored request from {src_ip}: Handshake not completed.")
                    continue

                self.client_ip = src_ip
                filename = packet.payload.decode('utf-8')
                print(f"Received request for '{filename}' from {src_ip}")
                
                self._send_file(filename)
                
                self.stats.write_report()
                
                # Reset state to accept the next file request
                self.stats = Stats()
                self.session_keys = None
                self.session_id = None
                self.client_ip = None
                self.raw_sock.enable_crypto(None, None)
                print("\nWaiting for next file request...")
        
        self.raw_sock.close_socket()
        print("Server finished.")


def main():
    """
    Entry point for the server program.
    """
    parser = argparse.ArgumentParser(description="SRFT Server")
    parser.add_argument("server_ip", help="This server's IP address", default=SERVER_IP)
    parser.add_argument("files_directory", nargs="?", default="./test_files", help="Directory for requested files")
    parser.add_argument("--insecure", action="store_true", help="Run without encryption")
    parser.add_argument("--attack", choices=["tamper", "replay", "inject"], default=None,
                        help="Built-in attack mode for security testing")

    args = parser.parse_args()

    server = SRFTServer(args.server_ip, args.files_directory, secure=not args.insecure, attack_mode=args.attack)
    server.start()


if __name__ == '__main__':
    main()