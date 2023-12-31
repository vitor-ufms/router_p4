#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import IP, TCP, ARP, Ether, get_if_hwaddr, get_if_list, sendp, ICMP

  
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

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='11:ff:ff:00:ff:00')
    #pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]

    # pkt = pkt /IP(dst=addr, ttl=1) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    #pkt = pkt / IP(dst=addr) / ICMP() # enviar ping

    #pkt = pkt /IP(dst=addr, ttl=6) / sys.argv[2]
    #pkt = pkt / ARP(op="who-has",pdst=addr) ## test for ARP

    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
