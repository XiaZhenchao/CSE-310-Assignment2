## High-level summary of the analysis_pcap_tcp code
## Part A
## A.a
In order to get the source port, source IP address, destination port, and destination IP address, I need to open the analysis_pcap_tcp.py file first, then read the packet one by one. For these packets, some are used for three times handshakes. Some are used for transmitting the packet. The difference between them is the length of the TCP.data. Once read the packet which the source port is never read before, and the length of TCP is greater than 0, then print all required information.
## A.b
The question is required to get the pieces of information of the first two transactions after the TCP connection is set up. Hence, these transactions are the packets right after the three handshake connections. After observing the data from the analysis_pcap_tcp.py file, I noticed that the length of the packets used for setting up the TCP connection is 0. And there are three different source ports in total. Hence, I only need to find the first two transactions in which the length is greater than 0 for different source ports, and there are six packets in total.
## A.c
The question requires the total amount of data sent by the sender. These data include the TCP connection. Through the observation, the start transaction's flag is 0x002, which is 2 in decimal, and the end transaction's flag is 0x011, which is 17 in decimal for all different source ports. Hence, we only need to record the start time, the end time, and the amount of data to print all necessary information.
## Part B.1
The congestion window sizes is the amount of packets sent in one RTT times. I can get the RTT time by using the time when sender sends the packet substract the time when sender receives the packet. Then get the time of the start point in three congestion window size for different portnumber. Then make a counter record the amount of the data send when time is between the start point time and start point time+ rtt.
## Part B.2
According to the piazza, TA said the retransmission due to time out = total retransmissions - retransmission due to triple duplicate ACK
RTO = 2 * RTT
If the time between the sender send the packet and receive the packet in one transaction less or equal than one RTO, and the sender send the packet for more than once, then this transaction is retransmission for duplicate ACKs.

### instructions on how to run codes
## Tools
Wireshark<br/>
Python 3.8<br/>
vscode<br/>
## instuctions
Please make sure the assignment2.pcap file is in the same file with analysis_pcap_tcp.py file, otherwise please change the value of PCIP_FILE variable which is to open the pcap file. Run the file, it will print the informations automatically.
