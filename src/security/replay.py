# Replay protection logic


class ReplayDetector:
    """Sliding-window replay detection (similar to IPsec/DTLS).

    Uses a bitmap to track which of the last *window_size* sequence numbers
    have been seen, keeping memory usage bounded while tolerating out-of-order
    delivery.
    """

    def __init__(self, window_size: int = 64) -> None:
        self.window_size = window_size
        self.highest_seq = -1
        self.bitmap = 0  # bitfield tracking seen seq_nums within the window

    def check_and_update(self, seq_num: int) -> bool:
        """Check whether *seq_num* is a replay and update internal state.

        Returns ``True`` if the packet is accepted (not a replay),
        ``False`` if it should be rejected.
        """
        if seq_num > self.highest_seq:
            # New packet ahead of the window — shift the bitmap.
            shift = seq_num - self.highest_seq
            self.bitmap <<= shift
            self.bitmap |= 1  # mark the new seq_num as seen
            # Mask off bits beyond the window size to keep bitmap bounded.
            self.bitmap &= (1 << self.window_size) - 1
            self.highest_seq = seq_num
            return True

        diff = self.highest_seq - seq_num
        if diff >= self.window_size:
            # Too old — outside the window.
            return False

        # Within the window — check/set the corresponding bit.
        bit = 1 << diff
        if self.bitmap & bit:
            return False  # already seen (replay)
        self.bitmap |= bit
        return True

    def reset(self) -> None:
        """Reset state for a new session."""
        self.highest_seq = -1
        self.bitmap = 0
