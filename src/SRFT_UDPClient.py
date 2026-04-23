# Main client program for Secure Reliable File Transfer.
# The client sends a file name request to the server, then sends the file request, receives the file data, 
# and verifies the integrity of the received file using SHA-256.
# The client also performs the handshake to establish session keys for encryption if the secure mode is enabled. 
# Finally, it prints the transfer statistics and saves a report to transfer_report.txt.

# Note: This code was written based on the book "Computer Networking: A Top-Down Approach" by Kurose and Ross, specifically chapter 3.4 
# 'Principles of Reliable Data Transfer', on reliable data transfer protocols (pipelined sliding window protocol). 
# We are using Go-Back-N (GBN) approach.

import os
import sys
import argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol.packet import Packet
from transport.raw_socket import RawSocket
from transport.receiver import Receiver
from config import MAX_RETRIES, SERVER_PORT, CLIENT_PORT, FLAG_REQ, SERVER_IP, CLIENT_IP, PSK, FLAG_CLIENT_HELLO, FLAG_STATS
from security.handshake import build_client_hello, parse_server_hello
from security.crypto import derive_session_keys
import time
import struct

class SRFTClient:
    #Parse command line arguments to get the filename to request from the server. Validate the filename and exit with an error message if it's invalid.
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="SRFT Client")
        parser.add_argument("filename", help="Name of the file to request from the server")
        parser.add_argument("--insecure", action="store_true", help="Run without encryption")

        args = parser.parse_args()

        filename = args.filename
        secure = not args.insecure

        #If the filename is empty or contains invalid characters, print an error message and exit.
        if not filename or any(c in filename for c in r'<>:"/\|?*'):
            print("SRFT Client: Error - Invalid filename. Filename cannot be empty or contain invalid characters.")
            sys.exit(1)

        return filename, secure

    # Initialize the client networking components by creating the raw socket and the receiver used to save incoming file data.
    @staticmethod
    def initialize_client(client_ip, output_filename):
        raw_socket = RawSocket(client_ip, CLIENT_PORT)
        raw_socket.set_timeout(0.05) #Set a timeout for socket operations to prevent hanging indefinitely
        receiver = Receiver(raw_socket, output_filename)
        
        return raw_socket, receiver

    # Perform the handshake with the server to establish session keys for encryption. 
    # Return the session keys and session ID if successful, or exit with an error message if the handshake fails after the maximum number of retries.
    @staticmethod
    def perform_handshake(raw_socket):
        print("SRFT Client: Initiating handshake...")
        payload, client_nonce = build_client_hello(PSK)
        hello_packet = Packet(seq_num=0, ack_num=0, flags=FLAG_CLIENT_HELLO, payload=payload)

        retries = MAX_RETRIES
        while retries > 0:
            raw_socket.send_packet(hello_packet, raw_socket.ip, CLIENT_PORT, SERVER_IP, SERVER_PORT)
            start_time = time.time()
            while time.time() - start_time < 2.0:
                packet, src_ip, src_port = raw_socket.receive_packet()
                if packet and packet.is_hello_server():
                    try:
                        server_nonce, session_id = parse_server_hello(PSK, client_nonce, packet.payload)
                        print("SRFT Client: Handshake successful.")
                        session_keys = derive_session_keys(PSK, client_nonce, server_nonce)
                        return session_keys, session_id
                    except Exception as e:
                        print(f"SRFT Client: Handshake verification failed - {e}")
                        sys.exit(1)
            retries -= 1
            print("SRFT Client: Handshake timeout, retrying...")

        print(f"SRFT Client: Handshake failed after {MAX_RETRIES} retries.")
        sys.exit(1)

    #Send a file request to the server by creating a packet with the filename and sending it to the server's IP and port.
    @staticmethod
    def send_file_request(raw_socket, filename):
        if raw_socket is None:
            print("SRFT Client: Error - Raw socket not initialized. Cannot send file request.")
            return
        
        # Create a packet containing the requested filename.
        req_packet = Packet(seq_num = 0, 
                            ack_num = 0, 
                            flags = FLAG_REQ, 
                            payload = filename.encode('utf-8'))
        
        # Send the request packet from the client's IP and port to the server's IP and port using the raw socket.
        raw_socket.send_packet(req_packet, 
                               raw_socket.ip, 
                               CLIENT_PORT, 
                               SERVER_IP, 
                               SERVER_PORT)
        print(f"SRFT Client: File request for '{filename}' sent to server.")
        
    #Send a file request to the server by creating a packet with the filename and sending it to the server's IP and port.
    # It is just a safety check to ensure the receiver is initialized before trying to receive packets.
    @staticmethod
    def receive_file_data(receiver):
        if receiver is None:
            print("SRFT Client: Error - Receiver not initialized. Cannot receive file data.")
            return
        
        receiver.receive_packets()
        
    # Safely close a raw socket if it was created, preventing resource leaks even if an earlier error occurred.
    @staticmethod
    def cleanup(raw_socket):
        if raw_socket is None:
            return
        try:
            raw_socket.close_socket()
        except Exception as e:
            print(f"SRFT Client: Warning - Error during cleanup: {e}")

    # Main client workflow: parse arguments, initialize networking, optionally perform the handshake, 
    # request the file, receive packets, verify SHA-256, and clean up resources.
    @staticmethod
    def main():
        #Initialize raw_socket to None. Finally clause will call cleanup even if the initialization fails.
        raw_socket = None

        try:
            #Handle all validation. Exit on valid input.
            filename, secure = SRFTClient.parse_arguments()
            print(f"Requesting file '{filename}' from server on port {SERVER_PORT}...")

            # Create output directory if it doesn't exist and construct the output file path for the received file.
            output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'output')
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, filename)

            # Create a raw socket for sending and receiving packets, and a receiver to handle incoming file data.
            raw_socket, receiver = SRFTClient.initialize_client(CLIENT_IP, output_path)

            # Check if the secure mode is enabled for the handshake. If yes, cryptography will be enabled on the raw socket.
            if secure:
                session_keys, session_id = SRFTClient.perform_handshake(raw_socket)
                raw_socket.enable_crypto(session_keys, session_id)
            else:
                print("SRFT Client: Running in insecure mode (no handshake).")

            print("SRFT Client: Sending file request to server...")
            SRFTClient.send_file_request(raw_socket, filename)
        
            print("SRFT Client: Waiting for server response...")
            SRFTClient.receive_file_data(receiver)

            if receiver.hash_match is True:
                print("SRFT Client: SHA-256 file verification: Match")
            elif receiver.hash_match is False:
                print("SRFT Client: SHA-256 file verification: Mismatch!") # File corruption detected
            else:
                print("SRFT Client: SHA-256 file verification: N/A")

            print(f"SRFT Client: AEAD authentication failures: {raw_socket.aead_failures}")
            print(f"SRFT Client: Replay packets dropped: {raw_socket.replay_drops}")

            # Send a final STATS packet back to the server so its
            # transfer_report.txt reflects the true AEAD / replay counts.
            # Those failures live on the client's receive path; the server
            # never sees them otherwise. Sent 3x for UDP reliability (no ACK
            # for this packet).
            try:
                stats_payload = struct.pack('!II', raw_socket.aead_failures, raw_socket.replay_drops)
                stats_packet = Packet(seq_num=0, ack_num=0, flags=FLAG_STATS, payload=stats_payload)
                for _ in range(3): # Send multiple times to increase chance of delivery since this is UDP and we won't get an ACK back.
                    raw_socket.send_packet(stats_packet, raw_socket.ip, CLIENT_PORT, SERVER_IP, SERVER_PORT)
                    time.sleep(0.05)
                print("SRFT Client: Sent final STATS packet to server.")
            except Exception as e:
                print(f"SRFT Client: Warning - could not send STATS packet: {e}")

            print("SRFT Client: File transfer complete. Closing connection...")

        except Exception as e:
            print(f"SRFT Client: Error - {e}")
            sys.exit(1)
        
        #Cleanup resources in the finally block to ensure they are released even if an error occurs.
        finally:
            SRFTClient.cleanup(raw_socket)

#Call the main function when the script is run directly
if __name__ == "__main__":
    SRFTClient.main()