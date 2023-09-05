import p4runtime_sh.shell as sh
from p4runtime_sh.shell import p4runtime_pb2 as p4runtime_proto


#you can omit the config argument if the switch is already configured with the
#correct P4 dataplane.
p4info = './build/basic.p4.p4info.txt'
bmv2_json = './build/basic.json'
sh.setup(
    device_id=1,
    grpc_addr='localhost:50051',
    election_id=(0, 1), # (high, low)
    #config=sh.FwdPipeConfig(p4info, bmv2_json)
)
print("teste")

#pktout = sh.PacketOut()

#a = sh.PacketIn()

#te = sh.read_table_entries()
#te = sh.tables()
#sh.main()
te = sh.TableEntry('ipv4_lpm')
#te = sh.TableEntry('MyIngress.arp_exact')
#print(te)

#te.match['<name>'] = '<value>'
# te.action['<name>'] = '<value>'
# te.insert()

sh.teardown()
