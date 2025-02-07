#!/usr/bin/env python3

# Copyright (c) 2018, 2020 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# This program can be used send L2-L7 protocol messages using the hex bytes
# of the packet, to test simple protocol scenarios. (e.g. generate simple
# nsh packets to test nsh match fields/actions)
#
# Currently, the script supports sending the packets starting from the
# Ethernet header. As a part of future enchancement, raw ip packet support
# can also be added, and that's why there is "-t"/"--type" option
#


import re
import socket
import sys
from optparse import OptionParser

try:
    from scapy.all import Ether, IP, IPv6, TCP, UDP, ARP, ICMP, ICMPv6ND_RA
    from scapy.all import ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU
    from scapy.all import ICMPv6NDOptPrefixInfo
    from scapy.all import ICMPv6EchoRequest, ICMPv6EchoReply
    SCAPY_PROTO = {
        "Ether": Ether,
        "IP": IP,
        "IPv6": IPv6,
        "TCP": TCP,
        "UDP": UDP,
        "ARP": ARP,
        "ICMP": ICMP,
        "ICMPv6ND_RA": ICMPv6ND_RA,
        "ICMPv6NDOptSrcLLAddr": ICMPv6NDOptSrcLLAddr,
        "ICMPv6NDOptMTU": ICMPv6NDOptMTU,
        "ICMPv6NDOptPrefixInfo": ICMPv6NDOptPrefixInfo,
        "ICMPv6EchoRequest": ICMPv6EchoRequest,
        "ICMPv6EchoReply": ICMPv6EchoReply,
    }

    def scapy_parse(packet_def):
        pkt_layers = packet_def.split("/")

        pkt = None

        for layer in pkt_layers:
            # Word(...) match
            lm = re.match(r'(\w+)\((.*?)\)', layer)
            if not lm:
                raise ValueError(
                    f"Invalid definition {packet_def} at layer {layer}")

            proto, proto_args_str = lm.groups()
            if proto not in SCAPY_PROTO:
                raise ValueError("Unable to construct a packet with {proto}.")

            proto_args = {}
            if proto_args_str:
                kvp = re.findall(r'(\w)=(?:\'([^\']*)\'|([\w.]+))',
                                 proto_args_str)
                for key, str_type, n_type in kvp:
                    proto_args[key] = str_type if str_type else eval(n_type)

            layer_obj = SCAPY_PROTO[proto](**proto_args)
            if pkt is None:
                pkt = layer_obj
            else:
                pkt /= layer_obj

        return pkt

except:
    def scapy_parse(packet_def):
        raise RuntimeError("No scapy module while trying to parse scapy def.")

usage = "usage: %prog [OPTIONS] OUT-INTERFACE HEX-BYTES \n \
         bytes in HEX-BYTES must be separated by space(s)"
parser = OptionParser(usage=usage)
parser.add_option("-t", "--type", type="string", dest="packet_type",
                  help="packet type ('eth' is the default PACKET_TYPE)",
                  default="eth")

(options, args) = parser.parse_args()

# validate the arguments
if len(args) < 2:
    parser.print_help()
    sys.exit(1)

# validate the "-t" or "--type" option
if options.packet_type != "eth":
    parser.error('invalid argument to "-t"/"--type". Allowed value is "eth".')

# Strip '0x' prefixes from hex input, combine into a single string and
# convert to bytes.
try:
    hex_str = "".join([a[2:] if a.startswith("0x") else a for a in args[1:]])
    pkt = bytes.fromhex(hex_str)
except ValueError:
    parsed_pkt_obj = scapy_parse(args[1])
    pkt = bytes(parsed_pkt_obj)

try:
    sockfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
except socket.error as msg:
    print('unable to create socket! error code: ' + str(msg[0]) + ' : '
                                                                    + msg[1])
    sys.exit(2)

try:
    sockfd.bind((args[0], 0))
except socket.error as msg:
    print('unable to bind socket! error code: ' + str(msg[0]) + ' : '
                                                                    + msg[1])
    sys.exit(2)

try:
    sockfd.send(pkt)
except socket.error as msg:
    print('unable to send packet! error code: ' + str(msg[0]) + ' : '
                                                                    + msg[1])
    sys.exit(2)

print('send success!')
sys.exit(0)
