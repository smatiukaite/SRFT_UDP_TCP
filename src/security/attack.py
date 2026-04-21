# Built-in attack modes for security testing (Phase 2)
# Implements --attack tamper, --attack replay, --attack inject
# These simulate real-world attacks so we can verify our security layer catches them.

import os
import struct


class AttackInterceptor:
    """
    Wraps the raw socket's send path to apply a single attack during a transfer.
    
    The server passes this interceptor's `send` method to Sender instead of 
    `_send_raw_packet`. Most packets pass through unchanged. One packet gets 
    the attack applied based on the mode.
    
    Modes:
        tamper  — flip two bits in one encrypted DATA packet (Test 3)
        replay  — store one DATA packet and resend it later (Test 4)
        inject  — send one forged garbage packet (Test 5)
    """

    def __init__(self, raw_socket, server_ip, server_port, client_ip, client_port, attack_mode: str):
        self.raw_socket = raw_socket
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.client_port = client_port
        self.attack_mode = attack_mode

        self.packet_count = 0
        self.attack_done = False

        # For replay: store one raw frame to resend later
        self.stored_frame = None

    def send(self, packet):
        """
        Drop-in replacement for SRFTServer._send_raw_packet.
        Passes the packet through normal send, then applies attack logic.
        """
        from protocol.packet import Packet

        self.packet_count += 1

        if self.attack_mode == "tamper" and not self.attack_done and self.packet_count == 5:
            # Send a tampered copy instead of the real packet for this one packet.
            # We let raw_socket encrypt it, then corrupt the raw bytes on the wire.
            self._send_tampered(packet)
            self.attack_done = True
            print(f"[ATTACK] Tampered packet #{self.packet_count} (flipped 2 bits in encrypted payload)")
            return

        # Normal send for all other cases
        self.raw_socket.send_packet(
            packet, self.server_ip, self.server_port, self.client_ip, self.client_port
        )

        if self.attack_mode == "replay" and not self.attack_done:
            # Store the 3rd packet's raw frame, replay it after the 8th
            if self.packet_count == 3:
                self.stored_frame = self._build_raw_frame(packet)
                print(f"[ATTACK] Stored packet #{self.packet_count} for replay")
            elif self.packet_count == 8 and self.stored_frame is not None:
                # Resend the stored frame as-is (duplicate/replay)
                self.raw_socket.sock.sendto(self.stored_frame, (self.client_ip, self.client_port))
                self.attack_done = True
                print(f"[ATTACK] Replayed stored packet after packet #{self.packet_count}")

        if self.attack_mode == "inject" and not self.attack_done and self.packet_count == 5:
            # Inject a forged packet with random garbage bytes
            self._send_forged()
            self.attack_done = True
            print(f"[ATTACK] Injected forged packet after packet #{self.packet_count}")

    def _send_tampered(self, packet):
        """
        Encrypt and assemble the packet normally, then flip 2 bits in the 
        UDP payload before sending. This will cause AEAD decryption failure 
        on the client.
        """
        from protocol.ip_header import build_ip_header
        from protocol.udp_header import build_udp_header
        from security.crypto import encrypt, build_aad

        # Encrypt the packet (same logic as raw_socket.send_packet)
        if self.raw_socket.session_keys:
            aad = build_aad(self.raw_socket.session_id, packet.seq_num, packet.ack_num, packet.flags)
            key = self.raw_socket.session_keys['enc_key']
            nonce, ciphertext = encrypt(key, packet.payload, aad)
            from protocol.packet import Packet as P
            packet = P(packet.seq_num, packet.ack_num, packet.flags, nonce + ciphertext)

        # Flip 2 bits in the ciphertext (payload = nonce[12] + ciphertext+tag)
        # Then rebuild the packet so the checksum is recomputed over the tampered
        # bytes — otherwise the receiver rejects it at the checksum layer before
        # AEAD ever runs.
        tampered_payload = bytearray(packet.payload)
        if len(tampered_payload) > 14:
            tampered_payload[13] ^= 0x01  # flip a bit in the ciphertext
            tampered_payload[14] ^= 0x02
        tampered_packet = P(packet.seq_num, packet.ack_num, packet.flags, bytes(tampered_payload))
        payload_bytes = tampered_packet.to_bytes()
        udp_header = build_udp_header(self.server_port, self.client_port, len(payload_bytes))
        ip_payload_length = len(udp_header) + len(payload_bytes)
        ip_header = build_ip_header(self.server_ip, self.client_ip, ip_payload_length)

        raw_frame = ip_header + udp_header + payload_bytes
        self.raw_socket.sock.sendto(raw_frame, (self.client_ip, self.client_port))

    def _build_raw_frame(self, packet):
        """
        Build the raw frame bytes for a packet (for storing/replaying).
        We re-encrypt here to get the exact bytes that would go on the wire.
        """
        from protocol.ip_header import build_ip_header
        from protocol.udp_header import build_udp_header
        from security.crypto import encrypt, build_aad

        if self.raw_socket.session_keys:
            aad = build_aad(self.raw_socket.session_id, packet.seq_num, packet.ack_num, packet.flags)
            key = self.raw_socket.session_keys['enc_key']
            nonce, ciphertext = encrypt(key, packet.payload, aad)
            from protocol.packet import Packet as P
            packet = P(packet.seq_num, packet.ack_num, packet.flags, nonce + ciphertext)

        payload_bytes = packet.to_bytes()
        udp_header = build_udp_header(self.server_port, self.client_port, len(payload_bytes))
        ip_payload_length = len(udp_header) + len(payload_bytes)
        ip_header = build_ip_header(self.server_ip, self.client_ip, ip_payload_length)

        return ip_header + udp_header + payload_bytes

    def _send_forged(self):
        """
        Send a forged packet with a valid SRFT header/checksum but bogus
        ciphertext. The checksum layer accepts it; AEAD rejects it because
        the GCM tag won't verify.
        """
        from protocol.ip_header import build_ip_header
        from protocol.udp_header import build_udp_header
        from protocol.packet import Packet as P
        from config import FLAG_DATA

        # Random bytes as the "encrypted" payload (nonce + ciphertext + tag).
        # Packet.to_bytes() computes a valid checksum so the receiver reaches AEAD.
        forged = P(seq_num=9999, ack_num=0, flags=FLAG_DATA, payload=os.urandom(150))
        payload_bytes = forged.to_bytes()

        udp_header = build_udp_header(self.server_port, self.client_port, len(payload_bytes))
        ip_payload_length = len(udp_header) + len(payload_bytes)
        ip_header = build_ip_header(self.server_ip, self.client_ip, ip_payload_length)

        raw_frame = ip_header + udp_header + payload_bytes
        self.raw_socket.sock.sendto(raw_frame, (self.client_ip, self.client_port))