# Phase 1 File Transfer Test

Following the instructions of the project, we set up the SRFT client and server on two separate machines in the same VPC. For phase 1, we did not enable encryption to focus on the reliability of the file transfer under packet loss conditions.

```sh
# Test the SRFT client and server with a 100MB file transfer

# On the server machine (test files are in the home directory)
sudo python3 src/SRFT_UDPServer.py "172.31.17.138" ~/ --insecure

# On the client machine
# Simulate 3% packet loss
sudo tc qdisc add dev ens5 root netem loss 3%
sudo SERVER_IP=172.31.17.138 CLIENT_IP=172.31.26.144 python3 src/SRFT_UDPClient.py test_100mb_file --insecure
```

`transfer_report.txt` generated on the server after the test:

```
Name of the transferred file: test_10mb_file
Size of the transferred file: 10485760 bytes
The number of packets sent from the server: 10241
The number of retransmitted packets from the server: 204
The number of packets received from the client: 2710
The time duration of the file transfer: 00:00:53
Encryption enabled: False
Handshake successful: False
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
Name of the transferred file: test_100mb_file
Size of the transferred file: 104857600 bytes
The number of packets sent from the server: 102401
The number of retransmitted packets from the server: 2912
The number of packets received from the client: 27704
The time duration of the file transfer: 00:10:52
Encryption enabled: False
Handshake successful: False
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
Name of the transferred file: test_500mb_file
Size of the transferred file: 524288000 bytes
The number of packets sent from the server: 512001
The number of retransmitted packets from the server: 15349
The number of packets received from the client: 139009
The time duration of the file transfer: 00:56:12
Encryption enabled: False
Handshake successful: False
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------

```

MD5 checksums of the original and received files:

```
TODO
```
