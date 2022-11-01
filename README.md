## High-level summary of the analysis_pcap_tcp code
## Part A
## A.a
In order to get the source port, source IP address, destination port, and destination IP address, I need to open the analysis_pcap_tcp.py file first, then read the packet one by one. For these packets, some are used for three times handshakes. Some are used for transmitting the packet. The difference between them is the length of the TCP.data. Once read the packet which the source port is never read before, and the length of TCP is greater than 0, then print all required information.
## A.b
The question is required to get the pieces of information of the first two transactions after the TCP connection is set up. Hence, these transactions are the packets right after the three handshake connections. After observing the data from the analysis_pcap_tcp.py file, I noticed that the length of the packets used for setting up the TCP connection is 0. And there are three different source ports in total. Hence, I only need to find the first two transactions in which the length is greater than 0 for different source ports, and there are six packets in total.
## A.c
The question requires the total amount of data sent by the sender. These data include the TCP connection. Through the observation, the start transaction's flag is 0x002, which is 2 in decimal, and the end transaction's flag is 0x011, which is 17 in decimal for all different source ports. Hence, we only need to record the start time, the end time, and the amount of data to print all necessary information.
## Part B
instructions on how to run codes
