from struct import pack
import dpkt
from dpkt.utils import inet_to_str
from regex import F
from sqlalchemy import false, true


PCIP_FILE = "assignment2.pcap"

class Flow:
    def __init__(self,SOURCE_PORT,SOURCE_IP,DESTI_PORT, DESTI_IP ,SEQ_NUM,ACK_NUM,WIN_SIZE):
        self.SOURCE_PORT = SOURCE_PORT
        self.SOURCE_IP = SOURCE_IP
        self.DESTI_PORT = DESTI_PORT
        self.DESTI_IP = DESTI_IP
        self.SEQ_NUM = SEQ_NUM
        self.ACK_NUM = ACK_NUM
        self.WIN_SIZE = WIN_SIZE

flowPort = []
SendFlow = []
ReceiveFlow = []
f = open(PCIP_FILE,'rb')
pcap = dpkt.pcap.Reader(f)
pcap = list(pcap)
counter = 1
totalData = 0
StartTime = 0.0
EndTime = 0.0

FlagForFirst = False
FlagForSecond = False
FlagForThird = False
WindowSizeCounter1 = 0
WindowSizeCounter2 = 0
WindowSizeCounter3 = 0
CheckSEQ = 0
ResendStartTime = 0.0
ResendEndTime = 0.0




#PartA.a
print("-----Part A.a-----")
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    
    if tcp.dport == 80:
        srcPort = tcp.sport
        dstPort = tcp.dport
        srcIP = ip.src
        dstIP = ip.dst
        
        if len(flowPort) == 0 and len(tcp.data)>0:
            flowPort.append(srcPort)
            print("source port: " + str(srcPort)+" source IP address: " + '.'.join(f'{c}' for c in srcIP) + 
            " destination port: " + str(dstPort)+ " destination IP address: " + '.'.join(f'{c}' for c in dstIP))

        if len(flowPort) > 0 and len(tcp.data)>0:
            if srcPort not in flowPort:
                flowPort.append(srcPort)
                print("source port: " + str(srcPort)+" source IP address: " + '.'.join(f'{c}' for c in srcIP) + 
                " destination port: " + str(dstPort)+ " destination IP address: " + '.'.join(f'{c}' for c in dstIP))
f.close()

#PartA.b
counter = 0
counter_Send = 2
if len(flowPort) != 0:
    while counter < len(flowPort):
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
    
            if tcp.dport == 80:
                srcPort = tcp.sport
                dstPort = tcp.dport
                srcIP = ip.src
                dstIP = ip.dst

            if len(tcp.data) > 0 and flowPort[counter] == srcPort and counter_Send >0:
                counter_Send = counter_Send - 1
                instance = Flow(srcPort,srcIP,dstPort,dstIP,tcp.seq,tcp.ack,tcp.win)
                ReceiveFlow.append(instance)
                TargetAck = tcp.seq + len(tcp.data)
                for ts, buf in pcap:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data
                    if TargetAck == tcp.ack and flowPort[counter] == tcp.dport:
                        instance2 = Flow(dstPort,dstIP, srcPort,srcIP,tcp.seq,tcp.ack,tcp.win)
                        SendFlow.append(instance2)

        counter = counter + 1
        counter_Send = 2

print("-----Part A.b-----")
for i in range(len(ReceiveFlow)):
    if i %2 == 0:
        print("Transaction: "+ str(int(i/2)+1))
    print(" source IP address: " + inet_to_str(ReceiveFlow[i].SOURCE_IP) +":"+str(ReceiveFlow[i].SOURCE_PORT)
    + " destination IP address: " + inet_to_str(ReceiveFlow[i].DESTI_IP)+":"+str(ReceiveFlow[i].DESTI_PORT) +" SEQ: "+ str(ReceiveFlow[i].SEQ_NUM) + " ACK: "+ str(ReceiveFlow[i].ACK_NUM))
    print(" source IP address: " + inet_to_str(SendFlow[i].SOURCE_IP) +":"+str(SendFlow[i].SOURCE_PORT)
    + " destination IP address: " + inet_to_str(SendFlow[i].DESTI_IP)+":"+str(SendFlow[i].DESTI_PORT)+" SEQ: "+ str(SendFlow[i].SEQ_NUM) + " ACK: "+ str(SendFlow[i].ACK_NUM))


#part A.c
print("-----Part A.c-----")

for i in range(len(flowPort)):
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        if tcp.sport == flowPort[i] and len(tcp)>0:
            totalData+=len(tcp)
        
        if tcp.sport == flowPort[i] and tcp.flags == 2:
            StartTime = ts
          
        if tcp.dport == flowPort[i] and tcp.flags == 17:
            EndTime = ts
            TotalTime = EndTime - StartTime
            print("Transaction"+ str(i+1))
            print("amount data: "+ str(totalData) + " Period of time: "+ str(TotalTime))
            print("Throughout: "+ str(totalData/TotalTime))
            StartTime = 0.0
            EndTime = 0.0
            totalData = 0


print("-----Part B-----")

for i in range(len(flowPort)):
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if flowPort[i] == tcp.sport and tcp.flags == 2: # find the first package's time for 3 times handshake
            rttStart = ts
        if flowPort[i] == tcp.dport and tcp.flags == 18:# find the last package's time for 3 times handshake
            rttEnd = ts
            rtt = rttEnd - rttStart                     # Get the rtt
        if flowPort[i] == tcp.sport and len(tcp.data)>0 and FlagForFirst == False:
            FirstPacketSendTime = ts
            FlagForFirst = True
        if flowPort[i]==tcp.sport and len(tcp.data)>0 and FlagForSecond==False and ts >= FirstPacketSendTime+rtt:
            SecondPacketSendTime = ts
            FlagForSecond = True
        if flowPort[i] == tcp.sport and len(tcp.data)>0 and FlagForThird == False and ts >= FirstPacketSendTime + rtt and ts >= SecondPacketSendTime + rtt:
            ThirdPacketSendTime = ts
            FlagForThird = True
 
    retransmission=[]
    retransmissionTime=[]
    CounterfoRetransmission = 0
    CounterforDuplicateACK = 0

    # Part B.1
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if ts >= FirstPacketSendTime and ts < FirstPacketSendTime + rtt and flowPort[i] == tcp.sport:
            WindowSizeCounter1 = WindowSizeCounter1+1
        elif ts >= SecondPacketSendTime and ts < SecondPacketSendTime + rtt and flowPort[i] == tcp.sport:
            WindowSizeCounter2 = WindowSizeCounter2+1
        elif ts >= ThirdPacketSendTime and ts < ThirdPacketSendTime + rtt and flowPort[i] == tcp.sport:
            WindowSizeCounter3 = WindowSizeCounter3+1   

    # Part B.2
        if(flowPort[i]==tcp.sport and len(tcp.data)>0 and tcp.seq not in retransmission ):
            retransmission.append(tcp.seq)
            retransmissionTime.append(ts)
        elif(flowPort[i]==tcp.sport and len(tcp.data)>0 and tcp.seq in retransmission):
            index=retransmission.index(tcp.seq)
            CounterfoRetransmission = CounterfoRetransmission + 1
            if(ts-retransmissionTime[index] <= rtt * 2) :
                CounterforDuplicateACK+=1
       
        
    print("-----Transaction: "+ str(i+1)+"-----")
    print("CongestionWindow1: "+str(WindowSizeCounter1))
    print("CongestionWindow2: "+str(WindowSizeCounter2))
    print("CongestionWindow3: "+str(WindowSizeCounter3))
    print("Retransmission due to duplicate ACK: " + str(CounterforDuplicateACK))
    print("retransmission occurred due to timeout: "+str(CounterfoRetransmission-CounterforDuplicateACK))
    WindowSizeCounter1 = 0
    WindowSizeCounter2 = 0
    WindowSizeCounter3 = 0
    FlagForFirst = False
    FlagForSecond = False
    FlagForThird = False




            


        

         
