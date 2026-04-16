# Send window, retransmission, timers

# Handles the sending side of reliable data transfer.
# Implements sliding window, timeout based retransmission, and ACK processing.

import threading
import time
from typing import Dict, List, Callable
from config import WINDOW_SIZE, TIMEOUT_INTERVAL, MAX_RETRIES, FLAG_DATA, FLAG_FIN
from protocol.packet import Packet


class Sender:
    """
    Manages reliable sending of packets using a sliding window protocol.
    
    How it works:
    1. We can send up to WINDOW_SIZE packets without waiting for ACKs
    2. Each unacknowledged packet has a timer
    3. If timer expires, we retransmit that packet
    4. When we receive an ACK, we slide the window forward
    
    This is similar to TCP's sliding window, but simplified.
    """
    
    def __init__(self, send_func: Callable[[Packet], None]):
        """
        Initialize the sender.
        
        Args:
            send_func: Function to call when we need to actually send a packet.
                       This gets provided by the main program and handles
                       the raw socket stuff. We just call send_func(packet).
        """
        self.send_func = send_func
        
        self.unacked_packets: Dict[int, tuple] = {}
        
        self.next_seq_num = 0
        
        
        self.base = 0
        
        
        self.lock = threading.Lock()
        
        self.running = True
        self.failed = False
        
        self.packets_sent = 0
        self.retransmissions = 0
        
        self.timer_thread = threading.Thread(target=self._timeout_checker, daemon=True)
        self.timer_thread.start()
    
    def send_packet(self, payload: bytes, flags: int = FLAG_DATA) -> bool:
        """
        Send a packet with the given payload.
        
        This might block if the window is full (we've sent WINDOW_SIZE
        packets that haven't been ACKed yet). We wait until there's room.
        
        Args:
            payload: The data to send (file chunk)
            flags: Packet flags (usually FLAG_DATA, or FLAG_FIN for last packet)
            
        Returns:
            True if sent successfully, False if max retries exceeded
        """
        
        
        while True:
            with self.lock:
                if self.next_seq_num < self.base + WINDOW_SIZE:
                    break  
            time.sleep(0.01)
        
        with self.lock:
            packet = Packet(
                seq_num=self.next_seq_num,
                ack_num=0,  
                flags=flags,
                payload=payload
            )
            
            self.send_func(packet)
            self.packets_sent += 1
            
            
            self.unacked_packets[self.next_seq_num] = (packet, time.time(), 0)
            
            self.next_seq_num += 1
        
        return True
    
    def handle_ack(self, ack_num: int):
        """
        Process a received ACK.
        
        ACKs are cumulative: an ACK for sequence number N means
        "I have received all packets up to and including N."
        
        So when we get ACK=5, we can remove packets 0,1,2,3,4,5 from
        our unacked list (if they're still there).
        
        Args:
            ack_num: The cumulative acknowledgment number received
        """
        
        with self.lock:
            
            to_remove = [seq for seq in self.unacked_packets if seq <= ack_num]
            for seq in to_remove:
                del self.unacked_packets[seq]
            
            
            if ack_num >= self.base:
                self.base = ack_num + 1
    
    def _timeout_checker(self):
        """
        Background thread that checks for packet timeouts.
        
        Runs continuously, checking if any unacked packets have been
        waiting too long. If so, retransmit them.
        
        This is how we handle packet loss: if we don't get an ACK
        in time, we assume the packet (or its ACK) was lost and resend.
        """
        
        while self.running:
            current_time = time.time()
            
            with self.lock:
                for seq_num, (packet, send_time, retry_count) in list(self.unacked_packets.items()):
                    if current_time - send_time > TIMEOUT_INTERVAL:
                        
                        if retry_count >= MAX_RETRIES:
                            print(f"ERROR: Max retries exceeded for packet {seq_num}")
                            self.failed = True
                            self.running = False
                            break
                        
                        self.send_func(packet)
                        self.retransmissions += 1
                        
                        self.unacked_packets[seq_num] = (packet, current_time, retry_count + 1)
            
            time.sleep(0.02)
    
    def all_acked(self) -> bool:
        """
        Check if all sent packets have been acknowledged.
        
        Used to know when file transfer is complete.
        
        Returns:
            True if nothing is waiting for ACK
        """
        with self.lock:
            return len(self.unacked_packets) == 0
    
    def wait_for_completion(self, timeout: float = 30.0) -> bool:
        """
        Block until all packets are acknowledged or timeout.
        
        Call this after sending the last packet to make sure
        everything got through before closing.
        
        Args:
            timeout: Maximum seconds to wait
            
        Returns:
            True if all ACKed, False if timed out
        """
        start_time = time.time()
        while not self.all_acked():
            if time.time() - start_time > timeout:
                return False
            time.sleep(0.05)
        return True
    
    def stop(self):
        """
        Stop the sender and its background thread.
        
        Call this when done sending to clean up resources.
        """
        self.running = False
        self.timer_thread.join(timeout=1.0)
    
    def get_stats(self) -> dict:
        """
        Get statistics for the output report.
        
        Returns:
            Dict with packets_sent and retransmissions counts
        """
        return {
            'packets_sent': self.packets_sent,
            'retransmissions': self.retransmissions
        }
