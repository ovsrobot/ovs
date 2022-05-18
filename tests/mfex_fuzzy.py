#!/usr/bin/python3

import sys

from scapy.all import RandMAC, RandIP, PcapWriter, RandIP6, RandShort, fuzz
from scapy.all import IPv6, Dot1Q, IP, Ether, UDP, TCP, random

# Relative path for the pcap file location.
path = str(sys.argv[1]) + "/pcap/fuzzy.pcap"
# The number of packets generated will be size * 8.
size = int(sys.argv[2])
# Traffic option is used to choose between fuzzy or simple packet type.
if (len(sys.argv) > 3):
    traffic_opt = str(sys.argv[3])
else:
    traffic_opt = ""

pktdump = PcapWriter(path, append=False, sync=True)

pkt = []

for i in range(0, size):
    if traffic_opt == "fuzzy":

        eth = Ether(src=RandMAC(), dst=RandMAC())
        vlan = Dot1Q()
        udp = UDP(dport=RandShort(), sport=RandShort())
        ipv4 = IP(src=RandIP(), dst=RandIP(), len=random.randint(0, 100))
        ipv6 = IPv6(src=RandIP6(), dst=RandIP6(), plen=random.randint(0, 100))
        tcp = TCP(dport=RandShort(), sport=RandShort(), flags='S',
                  dataofs=random.randint(0, 15))
        # IPv4 packets with fuzzing
        pkt.append(fuzz(eth / ipv4 / udp))
        pkt.append(fuzz(eth / ipv4 / tcp))
        pkt.append(fuzz(eth / vlan / ipv4 / udp))
        pkt.append(fuzz(eth / vlan / ipv4 / tcp))

        # IPv6 packets with fuzzing
        pkt.append(fuzz(eth / ipv6 / udp))
        pkt.append(fuzz(eth / ipv6 / tcp))
        pkt.append(fuzz(eth / vlan / ipv6 / udp))
        pkt.append(fuzz(eth / vlan / ipv6 / tcp))

    else:
        mac_addr = "52:54:00:FF:FF:%02x" % (random.randint(0, 255),)
        src_port = random.randrange(600, 800)
        dst_port = random.randrange(800, 1000)
        eth = Ether(src=mac_addr, dst=mac_addr)
        vlan = Dot1Q(vlan=random.randrange(1, 20))
        udp = UDP(dport=src_port, sport=dst_port)
        ipv4 = IP(src=RandIP()._fix(), dst=RandIP()._fix())
        ipv6 = IPv6(src=RandIP6()._fix(), dst=RandIP6()._fix())
        tcp = TCP(dport=src_port, sport=dst_port, flags='S')
        # IPv4 packets
        pkt.append(eth / ipv4 / udp)
        pkt.append(eth / ipv4 / tcp)
        pkt.append(eth / vlan / ipv4 / udp)
        pkt.append(eth / vlan / ipv4 / tcp)

        # IPv6 packets
        pkt.append(eth / ipv6 / udp)
        pkt.append(eth / ipv6 / tcp)
        pkt.append(eth / vlan / ipv6 / udp)
        pkt.append(eth / vlan / ipv6 / tcp)

pktdump.write(pkt)
