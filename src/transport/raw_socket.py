# Raw socket wrapper aka wire acess

# Note: This code was written based on the book "Computer Networking: A Top-Down Approach" by Kurose and Ross, specifically chapter 3.4 
# 'Principles of Reliable Data Transfer', on reliable data transfer protocols (pipelined sliding window protocol). We are using Go-Back-N (GBN) approach.

##This is shared by the client and the server.
##The class takes care of the below:
## 1.Creates the raw socket by using SOCK_RAW.
## 2.Builds IP+UDP headers.
## 3.Sends the headers.
## 4.Receives the raw frames and parses them into Packet objects.

##The goal of the raw socket is to turn a Packet object into bytes on the wire and wise versa: bytes in, bytes out.

import socket
import sys
from protocol.ip_header import build_ip_header, parse_ip_header
from protocol.packet import Packet
from protocol.udp_header import build_udp_header, parse_udp_header

class RawSocket:
    #Create the raw socket and bind it.
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        
        #Look for the root privileges.
        try:
            self.sock= socket.socket(socket.AF_INET, 
                                     socket.SOCK_RAW, 
                                     socket.IPPROTO_UDP)
        except PermissionError:
           print("ERROR! Root privileges required!")
           sys.exit(1)

        #Set the IP_HDRINCL option to tell the kernel that we will provide our own IP header.
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        #Bind the socket to the IP address. This is necessary to receive packets sent to this IP.
        try:
            self.sock.bind((self.ip, 0)) #We are binding to IP and any port (0). Will filter the packets by port in the receive function.
        except Exception as e:
            print(f"Error binding raw socket to {self.ip}: {e}")
            sys.exit(1)

    #Send the headers and the packet data.
    def send_packet (self, 
                     packet: Packet, 
                     source_ip: str, 
                     source_port: int, 
                     destination_ip: str, 
                     destination_port: int)-> None:
        payload_bytes = packet.to_bytes()
        udp_header = build_udp_header (source_port, destination_port, len(payload_bytes))
        ip_payload_length = len(udp_header) + len(payload_bytes)
        ip_header = build_ip_header (source_ip, destination_ip, ip_payload_length)
        
        raw_frame = ip_header + udp_header + payload_bytes
        self.sock.sendto(raw_frame, (destination_ip, destination_port))

    #Receive the raw frames and parses them into Packet objects.
    def receive_packet(self):
        try:
            frame_bytes, _ = self.sock.recvfrom(65535)
            ip_fields = parse_ip_header(frame_bytes)

            #Check case if the protocol is not UDP.
            if ip_fields['protocol'] != 17:
                return None, None, None

            #Calculate the length of the IP header to find where the UDP header starts.
            ip_header_length = ip_fields['header_length']
            udp_fields = parse_udp_header(frame_bytes[ip_header_length:])

            #Filter packets that are not destined for the SRFT port, because we might receive other UDP packets on this socket.
            if udp_fields['dst_port'] != self.port:
                return None, None, None

            # Skip UDP header (IP header + udp header).
            udp_header_length = 8
            payload_bytes = frame_bytes[ip_header_length + udp_header_length:]
            try:
                packet = Packet.from_bytes(payload_bytes)
                return packet, ip_fields['src_ip'], udp_fields['src_port']
            except ValueError as e:
                print(f"Packed was dropped! Corrupted! {e}")
                return None, None, None
            
        #Handle socket timeout. If no packet was received, return None, None.
        except socket.timeout:
            return None, None, None

    #Timeout in seconds for receive function.
    def set_timeout(self, seconds: float)-> None:
        self.sock.settimeout(seconds)

    #Close the socket.
    def close_socket(self)-> None:
        self.sock.close()