# Statistics and output report generation

# Transfer statistics and report generation.
# Tracks packets sent, retransmissions, and timing, then writes the required report file.


class Stats:
    def __init__(self):
        self.file_name = ""
        self.file_size = 0
        self.packets_sent = 0
        self.retransmissions = 0
        self.packets_received = 0
        self.start_time = 0
        self.end_time = 0
        self.encryption_enabled = False
        self.handshake_success = False
        self.aead_failures = 0
        self.replay_drops = 0

    def write_report(self):
        # Calculate transfer duration and format as hh:mm:ss.
        duration = self.end_time - self.start_time
        hours, rem = divmod(int(duration), 3600)
        mins, secs = divmod(rem, 60)

        report = (
            f"Name of the transferred file: {self.file_name}\n"
            f"Size of the transferred file: {self.file_size} bytes\n"
            f"The number of packets sent from the server: {self.packets_sent}\n"
            f"The number of retransmitted packets from the server: {self.retransmissions}\n"
            f"The number of packets received from the client: {self.packets_received}\n"
            f"The time duration of the file transfer: {hours:02}:{mins:02}:{secs:02}\n"
            f"Encryption enabled: {self.encryption_enabled}\n"
        )

        if self.encryption_enabled:
            report += (
                f"Handshake successful: {self.handshake_success}\n"
                f"AEAD authentication failures: {self.aead_failures}\n"
                f"Replay packets dropped: {self.replay_drops}\n"
            )

        print(report)

        # Write report to output file.
        with open("transfer_report.txt", "a") as f:
            f.write(report)
            f.write("\n" + "-" * 60 + "\n")
        print("Transfer report saved to transfer_report.txt")
