# Note: This code was written based on the book "Computer Networking: A Top-Down Approach" by Kurose and Ross, specifically chapter 3.4 
# 'Principles of Reliable Data Transfer', on reliable data transfer protocols (pipelined sliding window protocol). We are using 
# Go-Back-N (GBN).

# The Receiver class manages the receiving side of reliable data transfer. It handles:
# 1. Receiving packets from the raw socket.
# 2. 'Reordering out-of-order packets' by following the expected sequence number and dropping any packets that are duplicated or
# corrupted.
# 3. Sending cumulative ACKs.
# 4. Delivering in-order packets to the application layer.

# The class maintains a receive buffer for out-of-order packets and tracks the expected sequence number.
# The receiver accepts the next expected packet only. If it receives a packet with a higher sequence number, it buffers it and sends 
# an ACK for the last in-order packet received. If it receives a packet with the same sequence number, it repeats sending the ACK but 
# does not deliver it again.
from SRFT_UDP.cn_project.SRFT_UDP_TCP.config import FLAG_ACK, FLAG_FIN, FLAG_DATA
from SRFT_UDP.cn_project.SRFT_UDP_TCP.src.protocol.packet import Packet

class Receiver:
    #Create a constructor for receiver with the raw socket and output file path.
    def __init__(self, raw_socket, output_path):
        self.raw_socket = raw_socket
        self.file = open(output_path, 'wb')
        self.done = False
        
        self.peer_endpoint_ip = None
        self.peer_endpoint_port = None
       # self.receive_buffer = {}    # sequence_number -> packet
        self.expected_sequence_number = 0
        self.last_ack_sent = None

        self.total_packets_received = 0
        self.valid_packets_received = 0
        self.corrupted_packets = 0
        self.duplicated_packets = 0
        self.out_of_order_packets = 0

    #Receive the packets.
    def receive_packets(self):
        while not self.done:
            packet, source_ip, source_port = self.raw_socket.receive_header()

            if packet is not None:
                continue

            self.peer_endpoint_ip = source_ip
            self.peer_endpoint_port = source_port
            self.handle_packet(packet)
               
    #Handle a received packet.
    def handle_packet(self, packet):
        self.total_packets_received += 1

        #Check if the packet is corrupted by comparing the checksum. If yes, we drop the packet. If it was the first packet, we do not
        #  send an ACK. Otherwise we send the previous ACK.
        if packet.checksum != packet.calculate_checksum():
            self.handle_corrupted(packet)
            return

        #Expected sequence number.
        elif packet.sequence_number == self.expected_sequence_number:
            print(f"Received in order packet with sequence number {packet.sequence_number}.")
            self.handle_in_order(packet)

        #Duplicate packet.
        elif packet.sequence_number < self.expected_sequence_number:
            print(f"Received duplicate packet with sequence number {packet.sequence_number}, expected {self.expected_sequence_number}.")
            self.handle_duplicate(packet)
        
        #Out of order packet.
        else:
            print(f"Received out-of-order packet with sequence number {packet.sequence_number}, expected {self.expected_sequence_number}.")
            self.handle_out_of_order(packet)

    #Handle corrupted packet (a checksum mismatch).
    def handle_corrupted(self, packet):
        print(f"Received corrupted packet with sequence number {packet.sequence_number}.")
        self.corrupted_packets += 1
        
       # if self.expected_sequence_number == 0:
       #     print("First packet is corrupted, no ACK sent.")
       # else:
        if self.last_ack_sent is not None:
            print(f"Sending ACK for last in-order packet with sequence number {self.expected_sequence_number - 1}.")
            self.send_cumulative_ack(self.expected_sequence_number - 1)

    #Handle an in-order packet (expected sequence number).
    def handle_in_order(self, packet):
        self.file.write(packet.payload)
        self.file.flush()
        self.send_cumulative_ack(packet.sequence_number)
        #self.flush_buffered_packets()

        self.expected_sequence_number += 1
        self.received_correct_packets += 1
        
        if self.is_transfer_complete(packet):
            print("Received FIN, transfer complete.")
            self.done = True
            self.file.close()
    
    #Handle an out-of-order packet (higher than expected sequence number).
    def handle_out_of_order(self, packet):
        self.corrupted_packets += 1

       # self.receive_buffer[packet.sequence_number] = packet  
        self.send_cumulative_ack(self.expected_sequence_number - 1) #?
    
    #Handle a duplicate packet (same sequence number as last in-order). Needs retransmission, so we resend the ACK for the last 
    # in-order packet received.
    def handle_duplicate(self, packet):
        self.duplicated_packets += 1
        if self.expected_sequence_number > 0:
            self.send_cumulative_ack(packet.sequence_number)
            #self.flush_buffered_packets()

    #Flush buffered packets if they can now be delivered in order.
    #def flush_buffered_packets(self):
    #    
    #    print(f"Flushing buffered packets starting from expected sequence number {self.expected_sequence_number}.")
    
    #Send a cumulative ACK for the last in-order packet received.
    def send_cumulative_ack(self, ack_number):
        if ack_number == self.last_ack_sent:
            print(f"ACK for sequence number {ack_number} already sent, not sending duplicate ACK.")
            return

        if self.peer_endpoint_ip is None or self.peer_endpoint_port is None:
            print("Peer endpoint not known, cannot send ACK.")
            return
        

        ack = Packet(sequence_number = ack_number, flags = FLAG_ACK, payload=b'')

        self.raw_socket.send_header(ack, 
                                    source_ip = self.raw_socket.ip, 
                                    source_port = self.raw_socket.port,
                                    destination_ip = self.peer_endpoint_ip, 
                                    destination_port = self.peer_endpoint_port)
        
        self.last_ack_sent = ack_number
        print(f"Sent ACK for sequence number {ack_number}.")
    
    #Check if the transfer is complete, meaning we received FLAG_FIN = 1 and all packets up to FIN were delivered.
    def is_transfer_complete(self, packet):
        if packet.flags & FLAG_FIN and self.expected_sequence_number == packet.sequence_number + 1:
            return True