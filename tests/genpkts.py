#!/usr/bin/python3

import sys

from scapy.all import RandMAC, RandIP, RandIP6, RandShort, fuzz
from scapy.all import IPv6, Dot1Q, IP, Ether, UDP, TCP

if len(sys.argv) < 2:
    print('usage: {} packets_count [fuzz]'.format(sys.argv[0]))
    sys.exit(1)

tmpl = []

if len(sys.argv) == 2:
    eth = Ether(dst='ff:ff:ff:ff:ff:ff')
    vlan = eth / Dot1Q(vlan=1)
    p = eth / IP() / TCP(sport=20, dport=80, flags='SA', window=8192)
    tmpl += [p.build().hex()]
    p = eth / IP() / UDP(sport=53, dport=53)
    tmpl += [p.build().hex()]
    p = eth / IP() / TCP(sport=20, dport=80, flags='S', window=8192)
    tmpl += [p.build().hex()]
    p = eth / IP() / UDP(sport=53, dport=53)
    tmpl += [p.build().hex()]
    p = vlan / IP() / UDP(sport=53, dport=53)
    tmpl += [p.build().hex()]
    p = vlan / IP() / TCP(sport=20, dport=80, flags='S', window=8192)
    tmpl += [p.build().hex()]
elif sys.argv[2] == 'fuzz':
    # Generate random protocol bases, use a fuzz() over the combined packet
    # for full fuzzing.
    eth = Ether(src=RandMAC(), dst=RandMAC())
    vlan = Dot1Q()
    ipv4 = IP(src=RandIP(), dst=RandIP())
    ipv6 = IPv6(src=RandIP6(), dst=RandIP6())
    udp = UDP(dport=RandShort(), sport=RandShort())
    tcp = TCP(dport=RandShort(), sport=RandShort())

    # IPv4 packets with fuzzing
    tmpl += [fuzz(eth / ipv4 / udp).build().hex()]
    tmpl += [fuzz(eth / ipv4 / tcp).build().hex()]
    tmpl += [fuzz(eth / vlan / ipv4 / udp).build().hex()]
    tmpl += [fuzz(eth / vlan / ipv4 / tcp).build().hex()]

    # IPv6 packets with fuzzing
    tmpl += [fuzz(eth / ipv6 / udp).build().hex()]
    tmpl += [fuzz(eth / ipv6 / tcp).build().hex()]
    tmpl += [fuzz(eth / vlan / ipv6 / udp).build().hex()]
    tmpl += [fuzz(eth / vlan / ipv6 / tcp).build().hex()]

i = 0
count = int(sys.argv[1])
while count != 0:
    print(tmpl[i % len(tmpl)])
    i += 1
    count -= 1
