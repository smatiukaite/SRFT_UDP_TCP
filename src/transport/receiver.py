# Note: This code was written based on the book "Computer Networking: A Top-Down Approach" by Kurose and Ross, specifically chapter 3.4 
# 'Principles of Reliable Data Transfer', on reliable data transfer protocols (pipelined sliding window protocol). We are using Go-Back-N (GBN).

# The Receiver class manages the receiving side of reliable data transfer. It handles:
# 1. Receiving packets from the raw socket.
# 2. Accepting only the next expected packet, dropping duplicates/out-of-order packets, and sending cumulative ACKs.
# 3. Sending cumulative ACKs.
# 4. Delivering in-order packets to the application layer.

import hashlib
import time
from protocol.packet import Packet
from config import FLAG_ACK, FLAG_FIN, MAX_TIMEOUTS
from utils.file_handler import FileHandler
class Receiver:
    ACK_EVERY_N_PACKETS = 16
    ACK_DELAY_SECONDS = 0.01
    DEBUG = False

    #Create a constructor for receiver with the raw socket and output file path.
    def __init__(self, raw_socket, output_path):
        self.raw_socket = raw_socket
        self.file_handler = FileHandler()
        self.file_handler.open_output_file(output_path)
        self.done = False

        self.peer_endpoint_ip = None
        self.peer_endpoint_port = None

        #Go-Back-N style receiver state
        self.expected_sequence_number = 0
        self.last_ack_sent = None

        #Delayed ACK state
        self.pending_ack_deadline = None
        self.pending_ack_number = None
        self.in_order_since_last_ack = 0

        #Phase 2: SHA-256 file integrity verification state
        self.sha256 = hashlib.sha256()
        self.hash_match = None

        #Statistics tracking
        self.total_packets_received = 0
        self.valid_packets_received = 0
        self.corrupted_packets = 0
        self.duplicated_packets = 0
        self.out_of_order_packets = 0

    #Receive the packets.
    def receive_packets(self):
        timeout_count = 0
        
        while not self.done:
            packet, source_ip, source_port = self.raw_socket.receive_packet()
            now = time.time()

            if packet is None:
                #No packet received, likely a timeout. Increment the timeout count and check if we should abort.
                self.maybe_send_delayed_ack(now)

                timeout_count += 1
                if timeout_count >= MAX_TIMEOUTS:
                    print(f"Server may be down because no packet received for too long. Aborting.")
                    break
                continue

            #Reseting the timeout count on every successful packet reception.
            timeout_count = 0

            if self.peer_endpoint_ip is None:
                self.peer_endpoint_ip = source_ip
                self.peer_endpoint_port = source_port

            self.handle_packet(packet, now)

    #Handle a received packet.
    def handle_packet(self, packet, now = None):
        if now is None:
            now = time.time()

        self.total_packets_received += 1

        #Expected sequence number.
        if packet.seq_num == self.expected_sequence_number:
            if self.DEBUG and packet.seq_num % 500 == 0:
                print(f"Received in order packet with sequence number {packet.seq_num}...")
            self.handle_in_order(packet, now)

        #Duplicate packet.
        elif packet.seq_num < self.expected_sequence_number:
            if self.DEBUG:
                print(f"Received duplicate packet with sequence number {packet.seq_num}, expected {self.expected_sequence_number}.")
            self.handle_duplicate(packet)
        
        #Out of order packet.
        else:
            if self.DEBUG:
                print(f"Received out-of-order packet with sequence number {packet.seq_num}, expected {self.expected_sequence_number}.")
            self.handle_out_of_order(packet)

    #Handle corrupted packet (a checksum mismatch).
    def handle_corrupted(self, packet):
        if self.DEBUG:
            print(f"Received corrupted packet with sequence number {packet.seq_num}.")
        self.corrupted_packets += 1
        
        if self.expected_sequence_number > 0:
            if self.DEBUG:
                print(f"Sending ACK for last in-order packet with sequence number {self.expected_sequence_number - 1}.")
            self.send_cumulative_ack(self.expected_sequence_number - 1, force = True)

    #Handle an in-order packet (expected sequence number).
    def handle_in_order(self, packet, now = None):
        if now is None:
            now = time.time()

        # Check replay only for data packets that are accepted in order.
        if self.raw_socket.replay_detector and not packet.is_ack():
            if not self.raw_socket.replay_detector.check_and_update(packet.seq_num):
                print(f"Replay detected! Dropping packet with seq_num {packet.seq_num}")
                self.raw_socket.replay_drops += 1
                return
            
        self.expected_sequence_number += 1
        self.valid_packets_received += 1

        #Deliver the packet to the application layer (write to file).
        done = self.is_transfer_complete(packet)
        if done:
            # FIN packet: payload is the 32-byte SHA-256 digest from sender
            expected_hash = packet.payload
            if len(expected_hash) == 32:
                self.hash_match = (self.sha256.digest() == expected_hash)
                if self.hash_match:
                    print("SHA-256 file verification: Match")
                else:
                    print("SHA-256 file verification: Mismatch!")
            self.file_handler.write_payload_chunk(b'', done)
        else:
            self.sha256.update(packet.payload)
            self.file_handler.write_payload_chunk(packet.payload, done)
            
        self.pending_ack_number = packet.seq_num
        self.in_order_since_last_ack += 1

        #Start the ACK delay timer if it's not running already.
        if self.pending_ack_deadline is None:
            self.pending_ack_deadline = now + self.ACK_DELAY_SECONDS

        #Forse immediate ACK if we have reached the threshold of in-order packets since last ACK, or if this is the last packet (FIN).
        if done or self.in_order_since_last_ack >= self.ACK_EVERY_N_PACKETS:
            self.flush_pending_ack(force = False)

        if done:
            self.done = True

    #Handle an out-of-order packet (higher than expected sequence number).
    def handle_out_of_order(self, _packet):
        self.out_of_order_packets += 1

        if self.expected_sequence_number > 0:
            self.flush_pending_ack(force = False)
            self.send_cumulative_ack(self.expected_sequence_number - 1, force=True)
    
    #Handle a duplicate packet (same sequence number as last in-order). Needs retransmission, so we resend the ACK for the last 
    # in-order packet received.
    def handle_duplicate(self, _packet):
        self.duplicated_packets += 1
        
        if self.expected_sequence_number > 0:
            self.flush_pending_ack(force = False)
            self.send_cumulative_ack(self.expected_sequence_number - 1, force = True)
    
    def maybe_send_delayed_ack(self, now = None):
        if now is None:
            now = time.time()

        if (self.pending_ack_number is not None and self.pending_ack_deadline is not None and now >= self.pending_ack_deadline):
            self.flush_pending_ack(force = False)

    def flush_pending_ack(self, force = False):
        if self.pending_ack_number is None:
            return
        
        self.send_cumulative_ack(self.pending_ack_number, force = force)
        self.pending_ack_number = None
        self.pending_ack_deadline = None
        self.in_order_since_last_ack = 0

    #Send a cumulative ACK for the last in-order packet received.
    def send_cumulative_ack(self, ack_number, force = False):
        if ack_number == self.last_ack_sent and not force:
            if self.DEBUG:
                print(f"ACK for sequence number {ack_number} already sent, not sending duplicate ACK.")
            return

        if self.peer_endpoint_ip is None or self.peer_endpoint_port is None:
            if self.DEBUG:
                print("Peer endpoint not known, cannot send ACK.")
            return
        
        ack = Packet(seq_num = ack_number, ack_num = ack_number, flags = FLAG_ACK, payload = b'')

        self.raw_socket.send_packet(ack, 
                                    source_ip = self.raw_socket.ip, 
                                    source_port = self.raw_socket.port,
                                    destination_ip = self.peer_endpoint_ip, 
                                    destination_port = self.peer_endpoint_port)
        
        self.last_ack_sent = ack_number
        if self.DEBUG and ack_number % 500 == 0:
            print(f"Sent ACK for sequence number {ack_number}...")
    
    #Check if the transfer is complete, meaning we received FLAG_FIN = 1 and all packets up to FIN were delivered.
    def is_transfer_complete(self, packet):
        return bool(packet.flags & FLAG_FIN)