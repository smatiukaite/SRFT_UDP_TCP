# App-layer packet: seq, ack, flags, checksum, data

# Our custom application layer packet format.
# This sits inside the UDP payload and provides the reliability features:
# sequence numbers, acknowledgments, checksums, and flags.
# This is the heart of our reliable file transfer protocol.

import struct
from protocol.checksum import calculate_checksum, verify_checksum

# Our app-layer header is 14 bytes:


HEADER_SIZE = 14


class Packet:
    """
    Represents one packet in our protocol.
    
    A packet can be:
    - DATA: Carries a chunk of file data (has seq_num, payload)
    - ACK: Acknowledges received data (has ack_num, no payload)
    - FIN: Signals end of transfer (no payload)
    - REQ: Client requesting a file (payload = filename)
    
    The checksum covers the entire header + payload to detect corruption.
    """
    
    def __init__(self, seq_num: int = 0, ack_num: int = 0, flags: int = 0, payload: bytes = b''):
        """
        Create a new packet.
        
        Args:
            seq_num: Sequence number (which packet is this in the stream)
            ack_num: Acknowledgment number (cumulative: "I've received up to this")
            flags: Bitfield indicating packet type (DATA, ACK, FIN, REQ)
            payload: Actual data being carried (file chunk, filename, etc.)
        """
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.payload = payload
    
    def to_bytes(self) -> bytes:
        """
        Serialize this packet into bytes for transmission.
        
        We build the header with checksum=0 first, calculate the checksum
        over header+payload, then rebuild with the real checksum.
        
        Returns:
            Complete packet as bytes (header + payload)
        """
        
        payload_length = len(self.payload)
        
       
        header = struct.pack(
            '!IIHH H',
            self.seq_num,       # I: 4 bytes
            self.ack_num,       # I: 4 bytes
            self.flags,         # H: 2 bytes
            0,                  # H: 2 bytes (checksum placeholder)
            payload_length      # H: 2 bytes
        )
        
        packet_without_checksum = header + self.payload
        
        checksum = calculate_checksum(packet_without_checksum)
        
        header = struct.pack(
            '!IIHH H',
            self.seq_num,
            self.ack_num,
            self.flags,
            checksum,           
            payload_length
        )
        
        return header + self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Packet':
        """
        Deserialize bytes back into a Packet object.
        
        Used when receiving packets — we get raw bytes and need to
        extract the fields.
        
        Args:
            data: Raw bytes starting with our header
            
        Returns:
            Packet object with all fields populated
            
        Raises:
            ValueError: If checksum validation fails (corrupted packet)
        """
        
        if not verify_checksum(data):
            raise ValueError("Checksum verification failed — packet is corrupted")
        
        header_fields = struct.unpack('!IIHH H', data[:HEADER_SIZE])
        
        seq_num = header_fields[0]
        ack_num = header_fields[1]
        flags = header_fields[2]
        payload_length = header_fields[4]
        
        payload = data[HEADER_SIZE:HEADER_SIZE + payload_length]
        
        return cls(seq_num=seq_num, ack_num=ack_num, flags=flags, payload=payload)
    
    def is_data(self) -> bool:
        """Check if this is a DATA packet."""
        from config import FLAG_DATA
        return bool(self.flags & FLAG_DATA)
    
    def is_ack(self) -> bool:
        """Check if this is an ACK packet."""
        from config import FLAG_ACK
        return bool(self.flags & FLAG_ACK)
    
    def is_fin(self) -> bool:
        """Check if this is a FIN packet (end of transfer)."""
        from config import FLAG_FIN
        return bool(self.flags & FLAG_FIN)
    
    def is_request(self) -> bool:
        """Check if this is a file REQUEST packet."""
        from config import FLAG_REQ
        return bool(self.flags & FLAG_REQ)

    def is_hello_client(self) -> bool:
        """Check if this is a Client Hello packet."""
        from config import FLAG_CLIENT_HELLO
        return bool(self.flags & FLAG_CLIENT_HELLO)

    def is_hello_server(self) -> bool:
        """Check if this is a Server Hello packet."""
        from config import FLAG_SERVER_HELLO
        return bool(self.flags & FLAG_SERVER_HELLO)

    def __repr__(self) -> str:
        """Pretty print for debugging."""
        flag_names = []
        if self.is_data():
            flag_names.append('DATA')
        if self.is_ack():
            flag_names.append('ACK')
        if self.is_fin():
            flag_names.append('FIN')
        if self.is_request():
            flag_names.append('REQ')
        if self.is_hello_client():
            flag_names.append('HELLO_CLIENT')
        if self.is_hello_server():
            flag_names.append('HELLO_SERVER')
        
        flags_str = '|'.join(flag_names) if flag_names else 'NONE'
        
        return (f"Packet(seq={self.seq_num}, ack={self.ack_num}, "
                f"flags={flags_str}, payload_len={len(self.payload)})")