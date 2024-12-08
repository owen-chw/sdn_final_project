#!/usr/bin/env python3
import socket
import sys

from scapy.all import *

from probe_hdrs import *


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <destination>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print("sending on interface %s to %s" % (iface, str(addr)))

    while True:
        print()
        s = str(input('Type space separated port nums '
                          '(example: "2 3 2 2 1") or "q" to quit: '))
        if s == "q":
            break;
        print()

        i = 0
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff');
        for p in s.split(" "):
            try:
                pkt = pkt / RoutingLabel(bos=0, egress_spec=int(p))
                i = i+1
            except ValueError:
                pass
        if pkt.haslayer(RoutingLabel):
            pkt.getlayer(RoutingLabel, i).bos = 1

        pkt = pkt / Counter(visited_count=0) / IP(dst=addr) / UDP(dport=4321, sport=1234)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)

    #pkt = pkt / SourceRoute(bos=0, port=2) / SourceRoute(bos=0, port=3);
    #pkt = pkt / SourceRoute(bos=0, port=2) / SourceRoute(bos=0, port=2);
    #pkt = pkt / SourceRoute(bos=1, port=1)

if __name__ == '__main__':
    main()
