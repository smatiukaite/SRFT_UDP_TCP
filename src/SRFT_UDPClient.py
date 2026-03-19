# Client entry point

# Main client program for Secure Reliable File Transfer.
# The client sends a file name request to the server, then sends the file

# Note: This code was written based on the book "Computer Networking: A Top-Down Approach" by Kurose and Ross, specifically chapter 3.4 
# 'Principles of Reliable Data Transfer', on reliable data transfer protocols (pipelined sliding window protocol). We are using Go-Back-N (GBN) approach.

#SRFT_UDPClient takes a filename as input and sends that filename to the server to request the download,

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol.packet import Packet
from transport.raw_socket import RawSocket
from transport.receiver import Receiver
from config import SERVER_PORT, CLIENT_PORT, FLAG_REQ, SERVER_IP, CLIENT_IP

class SRFTClient:
    @staticmethod
    #Parse command line arguments to get the filename to request from the server. Validate the filename and exit with an error message if it's invalid.
    def parse_arguments():
        if len(sys.argv) != 2:
            print("SRFT Client: Error - No filename provided. Usage: SRFT_UDPClient.py <filename>")
            sys.exit(1)

        #Get the filename from command line.
        filename = sys.argv[1]

        #If the filename is empty or contains invalid characters, print an error message and exit.
        if not filename or any(c in filename for c in r'<>:"/\|?*'):
            print("SRFT Client: Error - Invalid filename. Filename cannot be empty or contain invalid characters.")
            sys.exit(1)

        return filename

    #Initialize the client by creating a raw socket, sender, receiver, and file handler. Return these objects for use in the main function.
    @staticmethod
    def initialize_client(client_ip, output_filename):
        raw_socket = RawSocket(client_ip, CLIENT_PORT)
        raw_socket.set_timeout(2.0) #Set a timeout for socket operations to prevent hanging indefinitely
        receiver = Receiver(raw_socket, output_filename)
        
        return raw_socket, receiver
    
    #Send a file request to the server by creating a packet with the filename and sending it to the server's IP and port.
    @staticmethod
    def send_file_request(raw_socket, filename):
        if raw_socket is None:
            print("SRFT Client: Error - Sender not initialized. Cannot send file request.")
            return
        
        req_packet = Packet(seq_num = 0, ack_num = 0, flags = FLAG_REQ, payload = filename.encode('utf-8'))
        raw_socket.send_packet(req_packet, raw_socket.ip, CLIENT_PORT, SERVER_IP, SERVER_PORT)
        print(f"SRFT Client: File request for '{filename}' sent to server.")
        
    #Send a file request to the server by creating a packet with the filename and sending it to the server's IP and port.
    @staticmethod
    def receive_file_data(receiver):
        if receiver is None:
            print("SRFT Client: Error - Receiver not initialized. Cannot receive file data.")
            return
        
        receiver.receive_packets()
        
    #Handle a corrupted packet by printing a message and dropping the packet. If it's the first packet, do not send an ACK. Otherwise, resend the previous ACK.
    @staticmethod
    def cleanup(raw_socket):
        if raw_socket is None:
            return
        try:
            raw_socket.close_socket()
        except Exception as e:
            print(f"SRFT Client: Warning - Error during cleanup: {e}")

    #Handle a corrupted packet by printing a message and dropping the packet. If it's the first packet, do not send an ACK. Otherwise, resend the previous ACK.
    @staticmethod
    def main():
        print("SRFT Client starting...")
        print("Please enter file name. Example of command: python SRFT_UDPClient.py fileName.txt")

        #Initialize raw_socket to None. Finally clause will call cleanup even if the initialization fails.
        raw_socket = None

        try:
            #Handle all validation. Exit on valid input.
            filename = SRFTClient.parse_arguments()
            print(f"Requesting file '{filename}' from server on port {SERVER_PORT}...")

            output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'output')
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, filename)
            raw_socket, receiver = SRFTClient.initialize_client(CLIENT_IP, output_path)

            print("SRFT Client: Sending file request to server...")
            SRFTClient.send_file_request(raw_socket, filename)
        
            print("SRFT Client: Waiting for server response...")
            SRFTClient.receive_file_data(receiver)

            print("SFRT Client: File transfer complete. Closing connection...")

        except Exception as e:
            print(f"SRFT Client: Error - {e}")
            sys.exit(1)
        
        #Cleanup resources in the finally block to ensure they are released even if an error occurs.
        finally:
            SRFTClient.cleanup(raw_socket)

#Call the main function when the script is run directly
if __name__ == "__main__":
    SRFTClient.main()