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

        self._dup_ack_num = -1
        self._dup_ack_count = 0
    
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
        
        # Wait until the window has space.
        while True:
            with self.lock:
                if self.next_seq_num < self.base + WINDOW_SIZE:
                    break  
            time.sleep(0.001) # saving some CPU while waiting for ACKs to slide the window.
        
        with self.lock:
            packet = Packet(
                seq_num=self.next_seq_num,
                ack_num=0,  
                flags=flags,
                payload=payload
            )
            
            self.send_func(packet)
            self.packets_sent += 1
            
            # Track this packet as unacknowledged, with the time it was sent and retry count.
            self.unacked_packets[self.next_seq_num] = (packet, time.time(), 0)
            
            self.next_seq_num += 1
        
        # Pacing delay OUTSIDE the lock: prevents bursting that overwhelms receiver.
        time.sleep(0.0002)

        return True

    # Handle an incoming ACK for the given sequence number and the sliding window logic.
    def handle_ack(self, ack_num: int):
        with self.lock:
            if ack_num < self.base:
                # Duplicate ACK — receiver is asking for self.base again
                if ack_num == self._dup_ack_num:
                    self._dup_ack_count += 1
                    if self._dup_ack_count == 3:
                        # Fast retransmit: immediately resend from base, don't wait for timeout
                        self._retransmit_from_base()
                else:
                    self._dup_ack_num = ack_num
                    self._dup_ack_count = 1
                return

            # New ACK — slide the window forward.
            to_remove = [seq for seq in self.unacked_packets if seq <= ack_num] # Remove all packets up to and including ack_num from unacked
            for seq in to_remove:
                del self.unacked_packets[seq]
            self.base = ack_num + 1
            self._dup_ack_count = 0
            self._dup_ack_num = -1


    def _retransmit_from_base(self):
        """Retransmit all unacked packets starting from base, in order (GBN semantics).
        Must be called while holding self.lock."""
        now = time.time()
        for seq_num in sorted(self.unacked_packets.keys()):
            packet, _, retry_count = self.unacked_packets[seq_num]
            if retry_count >= MAX_RETRIES:
                self.failed = True
                self.running = False
                return
            self.send_func(packet)
            self.retransmissions += 1
            self.unacked_packets[seq_num] = (packet, now, retry_count + 1)

        # Reset dup-ack state to prevent cascading retransmits.
        self._dup_ack_count = 0
        self._dup_ack_num = -1

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
                # Check if the oldest unacked packet (base) has timed out
                if self.base in self.unacked_packets:
                    _, send_time, _ = self.unacked_packets[self.base]
                    if current_time - send_time > TIMEOUT_INTERVAL:
                        # GBN: retransmit ALL unacked packets from base in order
                        self._retransmit_from_base()
            time.sleep(0.05)
    
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
