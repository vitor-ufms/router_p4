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
    rip_packet = RIP( cmd=1, version=2) # solicitando request
    # rip_packet = RIP( cmd=2, version=2) # enviando tabela

    # rip_entry = RIPEntry(metric=16)
    rip_entry = RIPEntry(AF=2, addr="33.0.0.4", mask="255.0.0.0", nextHop="33.0.2.2", metric=3)
    # rip_entry2 = RIPEntry(AF=2, addr="44.0.0.0", mask="255.0.0.0", nextHop="10.0.0.11", metric=1)
    # rip_entry3 = RIPEntry(AF=2, addr="11.0.0.0", mask="255.0.0.0", nextHop="10.0.0.11", metric=4)

    # Envie o pacote RIP
    # pkt = pkt / IP(dst="224.0.0.9", ttl=255)/ UDP(sport=520, dport=520)/ rip_packet / rip_entry/ rip_entry2 / rip_entry3
    pkt = pkt / IP(src="10.0.2.2",dst="224.0.0.9", ttl=255)/ UDP(sport=520, dport=520)/ rip_packet / rip_entry
    # pkt = pkt / IP(src="11.0.5.10", dst="10.0.2.15", ttl=255)/ UDP(sport=520, dport=520)/ rip_packet / rip_entry/ rip_entry2 / rip_entry3
    # pkt = pkt / IP(dst="127.0.0.1", ttl=255)/ TCP(sport=123, dport=2602)/ rip_packet / rip_entry/ rip_entry2 / rip_entry3


    sendp(pkt, verbose=False)
    pkt.show2()

if __name__ == '__main__':
    main()
