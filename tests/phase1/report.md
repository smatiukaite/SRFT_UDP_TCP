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
The number of packets sent from the server: 1281
The number of retransmitted packets from the server: 19
The number of packets received from the client: 96
The time duration of the file transfer: 00:00:01
Encryption enabled: False
Handshake successful: False
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
Name of the transferred file: test_100mb_file
Size of the transferred file: 104857600 bytes
The number of packets sent from the server: 12801
The number of retransmitted packets from the server: 128
The number of packets received from the client: 894
The time duration of the file transfer: 00:00:11
Encryption enabled: False
Handshake successful: False
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
Name of the transferred file: test_500mb_file
Size of the transferred file: 524288000 bytes
The number of packets sent from the server: 64001
The number of retransmitted packets from the server: 256
The number of packets received from the client: 4091
The time duration of the file transfer: 00:00:53
Encryption enabled: False
Handshake successful: False
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
Name of the transferred file: test_800mb_file
Size of the transferred file: 838860800 bytes
The number of packets sent from the server: 102401
The number of retransmitted packets from the server: 623
The number of packets received from the client: 6784
The time duration of the file transfer: 00:02:02
Encryption enabled: False
Handshake successful: False
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------
Name of the transferred file: test_1gb_file
Size of the transferred file: 1073741824 bytes
The number of packets sent from the server: 131073
The number of retransmitted packets from the server: 636
The number of packets received from the client: 8578
The time duration of the file transfer: 00:01:49
Encryption enabled: False
Handshake successful: False
AEAD authentication failures: 0
Replay packets dropped: 0
SHA-256 file verification: N/A

------------------------------------------------------------

```

MD5 checksums of the original and received files:

```
f1c9645dbc14efddc7d8a322685f26eb  test_10mb_file
2f282b84e7e608d5852449ed940bfc51  test_100mb_file
d8b61b2c0025919d5321461045c8226f  test_500mb_file
4067155e98ab9e162baab0b6341f275a  test_800mb_file
cd573cfaace07e7949bc0c46028904ff  test_1gb_file
```
