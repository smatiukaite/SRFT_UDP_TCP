from security.replay import ReplayDetector

class TestReplayDetector:
    def test_rejects_out_of_order_duplicate_within_window(self):
        detector = ReplayDetector(window_size=8)
        assert detector.check_and_update(10) is True
        assert detector.check_and_update(8) is True

        # Duplicate of 8 should be rejected
        assert detector.check_and_update(8) is False

    def test_rejects_exact_duplicate(self):
        detector = ReplayDetector()
        assert detector.check_and_update(5) is True
        assert detector.check_and_update(5) is False

    def test_accepts_first_packet(self):
        detector = ReplayDetector(window_size=64)
        assert detector.check_and_update(1) is True

    def test_accepts_strictly_increasing_sequence_numbers(self):
        detector = ReplayDetector()
        for seq in range(1, 4):
            assert detector.check_and_update(seq) is True

    def test_accepts_out_of_order_packet_within_window_once(self):
        detector = ReplayDetector(window_size= 8)
        assert detector.check_and_update(10) is True
        assert detector.check_and_update(8) is True

    def test_rejects_packet_older_than_window(self):
        detector = ReplayDetector(window_size=4)
        assert detector.check_and_update(10) is True
        assert detector.check_and_update(2) is False
        assert detector.check_and_update(1) is False

    def test_reset_clears_state(self):
        detector = ReplayDetector(window_size=8)
        assert detector.check_and_update(3) is True
        assert detector.check_and_update(4) is True
        detector.reset()
        assert detector.check_and_update(3) is True
    
    def test_large_jump_advances_window_correctly(self):
        detector = ReplayDetector(window_size=8)
        assert detector.check_and_update(1) is True
        assert detector.check_and_update(100) is True
        assert detector.check_and_update(100) is False