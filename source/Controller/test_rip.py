#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import IP, TCP, ARP, Ether, get_if_hwaddr, get_if_list, sendp, ICMP, RIP, UDP, RIPEntry

  
# def get_if():
#     ifs=get_if_list()
#     iface=None # "h1-eth0"
#     for i in get_if_list():
#         if "eth0" in i:
#             iface=i
#             break;
#     if not iface:
#         print("Cannot find eth0 interface")
#         exit(1)
#     return iface

def main():

    
    #iface = get_if()

    #print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether()
    # pkt =  Ether(src='11:ff:ff:00:ff:10',  dst='ff:ff:ff:ff:ff:ff')
    rip_packet = RIP( cmd=2, version=2)


    rip_entry = RIPEntry(AF=2, addr="192.0.11.0", mask="255.255.255.0", nextHop="10.0.0.10", metric=1)
    rip_entry2 = RIPEntry(AF=2, addr="192.0.22.0", mask="255.255.0.0", metric=10)
    # Envie o pacote RIP
    pkt = pkt / IP(dst="224.0.0.9", ttl=6)/ UDP(sport=520, dport=520)/ rip_packet / rip_entry/ rip_entry2

    sendp(pkt, verbose=False)
    pkt.show2()

if __name__ == '__main__':
    main()
