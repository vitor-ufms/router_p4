import subprocess, ipaddress, time, sys
from threading import Thread

import p4runtime_sh.shell as sh
from p4runtime_sh.shell import p4runtime_pb2 as p4runtime_proto
import random, socket, sys
from scapy.all import IP, TCP, ARP, Ether, get_if_hwaddr, get_if_list, sendp, UDP, RIP, RIPEntry
import p4runtime_shell_utils as p4rtutil


p4info = './../build/basic.p4.p4info.txt'
bmv2_json = './../build/basic.json'

p4info_data = p4rtutil.read_p4info_txt_file(p4info)
p4info_obj_map = p4rtutil.make_p4info_obj_map(p4info_data)
cpm_packetin_id2data = p4rtutil.controller_packet_metadata_dict_key_id(p4info_obj_map, "packet_in")


sh.setup(
        device_id=0,
        grpc_addr='localhost:50051',
        election_id=(0, 1), # (high, low)
        #config=sh.FwdPipeConfig(p4info, bmv2_json)
    )

# see p4runtime_sh/test.py for more examples
te = sh.TableEntry('ipv4_lpm')(action='ipv4_forward')
# te.match['<name>'] = '<value>'
# te.action['<name>'] = '<value>'
# te.insert()
print(te)