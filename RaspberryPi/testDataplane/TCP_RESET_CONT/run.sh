#!/bin/bash

while true; do
    grep -q '^1$' "/sys/class/net/eth0/carrier" &&
	grep -q '^1$' "/sys/class/net/eth1/carrier" &&
	break

    sleep 1

done

brctl addbr bridge0
ifconfig eth0 down
ifconfig eth1 down
brctl addif bridge0 eth0 eth1
ifconfig eth0 up
ifconfig eth1 up
ifconfig bridge0 up


iptables -A FORWARD -p tcp --syn --dport 5201 -m connlimit  --connlimit-above 10 -j REJECT --reject-with tcp-reset &&
#iptables -A FORWARD -p icmp -j DROP
tcpdump port 5201 -w sample-aegis.pcap && /bin/bash
#python scapy.py > samp1.txt && /bin/bash 
