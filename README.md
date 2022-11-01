###High-level summary of the analysis_pcap_tcp code
###Part A
###A.a
In order to get the source port, source IP address, destination port, destination IP address, I need to open the analysis_pcap_tcp.py file first, then read
packet one by one. For these packets, some are used for three times handshake, some are used for transmit the packet. The difference between them is the
length of the tcp.data. Once read the packet which the source port is never read before and the length of tcp is greater than 0, then, print all required
informations
###A.b
###Part B
instructions on how to run codes
