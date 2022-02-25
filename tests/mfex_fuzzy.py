#!/usr/bin/python3

import sys

from scapy.all import RandMAC, RandIP, PcapWriter, RandIP6, RandShort, fuzz
from scapy.all import IPv6, Dot1Q, IP, Ether, UDP, TCP, random

path = str(sys.argv[1]) + "/pcap/fuzzy.pcap"
size = int(sys.argv[2])
traffic_opt = str(sys.argv[3])

pktdump = PcapWriter(path, append=False, sync=True)

for i in range(0, size):

    eth = Ether(src=RandMAC(), dst=RandMAC())
    vlan = Dot1Q()
    ipv4 = IP(src=RandIP(), dst=RandIP(), len=random.randint(0, 100))
    ipv6 = IPv6(src=RandIP6(), dst=RandIP6(), plen=random.randint(0, 100))
    udp = UDP(dport=RandShort(), sport=RandShort())
    tcp = TCP(dport=RandShort(), sport=RandShort(), flags='S', dataofs=(0, 20))

    if traffic_opt == "fuzzy":

        # IPv4 packets with fuzzing
        pktdump.write(fuzz(eth / ipv4 / udp))
        pktdump.write(fuzz(eth / ipv4 / tcp))
        pktdump.write(fuzz(eth / vlan / ipv4 / udp))
        pktdump.write(fuzz(eth / vlan / ipv4 / tcp))

        # IPv6 packets with fuzzing
        pktdump.write(fuzz(eth / ipv6 / udp))
        pktdump.write(fuzz(eth / ipv6 / tcp))
        pktdump.write(fuzz(eth / vlan / ipv6 / udp))
        pktdump.write(fuzz(eth / vlan / ipv6 / tcp))

    else:

        # IPv4 packets
        pktdump.write(eth / ipv4 / udp)
        pktdump.write(eth / ipv4 / tcp)
        pktdump.write(eth / vlan / ipv4 / udp)
        pktdump.write(eth / vlan / ipv4 / tcp)

        # IPv6 packets
        pktdump.write(eth / ipv6 / udp)
        pktdump.write(eth / ipv6 / tcp)
        pktdump.write(eth / vlan / ipv6 / udp)
        pktdump.write(eth / vlan / ipv6 / tcp)
