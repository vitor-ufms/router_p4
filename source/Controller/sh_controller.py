import p4runtime_sh.shell as sh
from p4runtime_sh.shell import p4runtime_pb2 as p4runtime_proto
import p4runtime_shell_utils as p4rtutil

import random
import socket
import sys

from scapy.all import IP, TCP, ARP, Ether, get_if_hwaddr, get_if_list, sendp

#you can omit the config argument if the switch is already configured with the
#correct P4 dataplane.
p4info = './../build/basic.p4.p4info.txt'
bmv2_json = './../build/basic.json'
sh.setup(
    device_id=0,
    grpc_addr='localhost:50051',
    election_id=(0, 1), # (high, low)
    #config=sh.FwdPipeConfig(p4info, bmv2_json)
)
print("teste")

p4info_data = p4rtutil.read_p4info_txt_file(p4info)
p4info_obj_map = p4rtutil.make_p4info_obj_map(p4info_data)
#cpm_packetin_id2data = p4rtutil.controller_packet_metadata_dict_key_id(p4info_obj_map, "packet_in")


#######################################################################
pktin = sh.PacketIn()
#pktout = sh.PacketOut()

for i in range(10):
    pktlist = []
    #pktin.sniff(lambda p: pktlist.append(p), timeout=2)
    #print(list(pktin.sniff(function=None, timeout=None)))
    try:
        # print(type(pktin.packet_in_queue.get(block=True, timeout=0.5)))
        pk = pktin.packet_in_queue.get(block=True, timeout=2)
        #print(dir(pk))
        print(pk.packet.payload)
        packet_bytes = pk.packet.payload

        #print(pk)
        #print('-------                   ---------------')
        # pktinfo = p4rtutil.decode_packet_in_metadata(
        #              cpm_packetin_id2data, pk.packet)
        # packet_bytes = pktinfo['payload']
        #print(packet_bytes)
        #packet_bytes= pktinfo['payload']
        # Use Ether() para criar um objeto Scapy a partir dos bytes
        eth_packet = Ether(packet_bytes)


        # Agora você pode manipular o objeto Scapy normalmente
        eth_packet.show()
      
        # for pkg in pk.packet.metadata:
        #     print('======')
        #     print(pkg.value)
        #     print(int.from_bytes(pkg.value, byteorder='little'))
        #     print(int.from_bytes(pkg.value, byteorder='big'))           
        #     print('====+++++')
    except :
        pass

    #print(pktlist)

    print("-----------------------------------------------  ", i)
#############################################################################


# pkt = Ether(dst='00:00:00:00:00:00')
#pktout = sh.PacketOut()
# pktout.payload = bytes(pkt)
#pktout.payload = packet_bytes
# pktout.metadata['opcode'] = '2'
# pktout.metadata['operand0'] =  '2'  #'%d' % (idx_int)
# pktout.metadata['operand1'] = '0'
#pktout.send()


#te = sh.read_table_entries()
#te = sh.tables()
#sh.main()
#te = sh.TableEntry('ipv4_lpm')
#te = sh.TableEntry('MyIngress.arp_exact')
#print(te)

#te.match['<name>'] = '<value>'
# te.action['<name>'] = '<value>'
# te.insert()

sh.teardown()
