# Vitor Hugo dos Santos Duarte
#

import subprocess, ipaddress, time
from threading import Thread

import p4runtime_sh.shell as sh
from p4runtime_sh.shell import p4runtime_pb2 as p4runtime_proto
import random, socket, sys
from scapy.all import IP, TCP, ARP, Ether, get_if_hwaddr, get_if_list, sendp
import p4runtime_shell_utils as p4rtutil


p4info = './../build/basic.p4.p4info.txt'
bmv2_json = './../build/basic.json'

p4info_data = p4rtutil.read_p4info_txt_file(p4info)
p4info_obj_map = p4rtutil.make_p4info_obj_map(p4info_data)
cpm_packetin_id2data = p4rtutil.controller_packet_metadata_dict_key_id(p4info_obj_map, "packet_in")

# list with queued packages
queue_arp = []
CLEAR_TABLE = 1
TIME_CLEAR_TABLE = 20

#Thd1 = Thread(target=email,args=[EMAIL, PASSWORD]) # Cria uma thread
# limpa todas as entradas da tabela - não testado
def table_clear(sw,table):
    while CLEAR_TABLE: 
        time.sleep(TIME_CLEAR_TABLE) # segundos
        print('limpando... ',table)
        input_str = "table_clear %s \n" % table
        sw.stdin.write(input_str)
        sw.stdin.flush()  # Certifique-se de que a entrada seja enviada imediatamente


def connection(thrift_port = 9090):
    sw = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], \
                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sw.stdout.readline().strip() # Obtaining JSON from switch...
    sw.stdout.readline().strip() # Done
    sw.stdout.readline().strip() # Control utility for runtime P4 table manipulation
    return sw

def connection_sh():
    sh.setup(
        device_id=0,
        grpc_addr='localhost:50051',
        election_id=(0, 1), # (high, low)
        #config=sh.FwdPipeConfig(p4info, bmv2_json)
    )
    #return sh

def read_register(sw, register, idx, ptr = False):
    input_str = "register_read %s %d \n" % (register, idx)
    
    if ptr:
        print(input_str[0:-1])

    # Envie os dados de entrada para o processo e capture a saída
    sw.stdin.write(input_str)
    sw.stdin.flush()  # Certifique-se de que a entrada seja enviada imediatamente

    stdout_str = sw.stdout.readline().strip()
    reg_val = stdout_str.split('= ', 1)[1] # divide a string em duas partes, no máximo 1 vez, e salva a segunda posição[1]
    #print(stdout_str)
    return int(reg_val)

def write_register(sw, register, idx=0, value=0, ptr = False): # name, index, value

    input_str = "register_write %s %d %d \n" % (register, idx, value)
    if ptr:
        print(input_str[0:-1])

    # Envie os dados de entrada para o processo e capture a saída
    sw.stdin.write(input_str)
    sw.stdin.flush()  # Certifique-se de que a entrada seja enviada imediatamente

def ip_to_decimal(ip_str, ptr=False):
    # Endereço IP no formato "10.0.2.192"
    # Obter o valor decimal do endereço IP
    decimal_value = int(ipaddress.IPv4Address(ip_str))
    # Imprimir o valor decimal
    if ptr:
        print("Valor Decimal:", decimal_value)
    return decimal_value

def decimal_to_ip(decimal_value, ptr=False):
    # Obter o endereço IP no formato "x.x.x.x"
    ip_str = str(ipaddress.IPv4Address(decimal_value))
    if ptr:
        print("Endereço IP:", ip_str)
    return ip_str
def mac_hex_to_mac_format(mac_hex):
    mac_formatado = ":".join([mac_hex[i:i+2] for i in range(0, len(mac_hex), 2)]) # fomata uma string em hexa para o foramato mac
    return mac_formatado

def ip_hex_to_ip_format(ip_hex):
    ip_formatado = ".".join(str(int(ip_hex[i:i+2], 16)) for i in range(0, len(ip_hex), 2)) 
    return ip_formatado

def table_add(sw, table, action, val_in, val_out, ptr=False, clean=0): #table_add MyIngress.arp_exact arp_answer 10.0.11.10/32 => 00:11:22:33:44:55
    
    input_str = "table_add %s %s %s => %s \n" % (table, action, val_in, val_out)
    
    if ptr:
        print(input_str[0:-1])

    # Envie os dados de entrada para o processo e capture a saída
    sw.stdin.write(input_str)
    sw.stdin.flush()  # Certifique-se de que a entrada seja enviada imediatamente
    for i in range(clean):
        sw.stdout.readline().strip()

# table_dump_entry_from_key <table name> <match fields>
def table_from_key(sw, table, key, clean=0, ptr = False):
    input_str = "table_dump_entry_from_key %s %d \n" % (table, key)
    sw.stdin.write(input_str)
    sw.stdin.flush()  # Certifique-se de que a entrada seja enviada imediatamente
    for i in range(clean):
        sw.stdout.readline().strip()
    
    stdout_str = sw.stdout.readline().strip()
    #print(stdout_str)
    mac_hex = stdout_str.split('- ', 1)[1].split(',', 1)[0]
    ip_hex = stdout_str.split(', ', 1)[1]

    mac_formatado = mac_hex_to_mac_format(mac_hex)
    ip_formatado = ip_hex_to_ip_format(ip_hex)

    return mac_formatado, ip_formatado


def init_reg(sw): # não usa mais essa lógica
    reg = 'interface_ip'
    value_ip = ip_to_decimal('10.0.11.10')
    write_register(sw,register=reg, idx=1, value=value_ip, ptr = True)
    value_ip = ip_to_decimal('10.0.11.10')
    write_register(sw,register=reg, idx=2, value=value_ip, ptr = True)
    value_ip = ip_to_decimal('10.0.33.10')
    write_register(sw,register=reg, idx=3, value=value_ip, ptr = True)
    value_ip = ip_to_decimal('10.0.44.10')
    write_register(sw,register=reg, idx=4, value=value_ip, ptr = True)

    reg_val2 = read_register(sw, register='interface_ip', idx=1, ptr=True)
    print(reg_val2)
    reg_val = read_register(sw, register='interface_ip', idx=2, ptr=True)
    print(reg_val)
    reg_val = read_register(sw, register='interface_ip', idx=3, ptr=True)
    print(reg_val)
    reg_val = read_register(sw, register='interface_ip', idx=4, ptr=True)
    print(reg_val)

def init_table(sw):
    #MyIngress.arp_exact arp_answer 10.0.11.10/32 => 00:11:22:33:44:55
    table = 'MyIngress.ipv4_lpm'; action = 'ipv4_forward'
    v_in = '10.0.11.1/32' ; v_out='5 00:11:22:33:44:55 00:11:22:33:44:55'
    table_add(sw, table, action, v_in, v_out)
    sw.stdout.readline().strip() # Entry has been added  with handle x

def packet_out_request(sw, por_dst,ip_dst):
    # qual o mac da interface de saída?
    a = table_from_key(sw,'pre_proc', por_dst, clean=3) # a[0]= mac a[1]= ip

    pkt = Ether(src=a[0], dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / ARP(op="who-has", hwsrc=a[0], psrc=a[1], pdst=ip_dst)
    
    #pkt.show() # pacote que será enviado
    pkt_out.payload = bytes(pkt)
    pkt_out.metadata['operand0'] = str(por_dst) ## interface 

    #pktout.metadata['operand1'] = '0'
    pkt_out.send()

# recebe um pacote que não tem correspondência na tabela ARP, salva o  pacote e abre uma chamada ARP request
def arp_request(sw, reg = 'controller_op'):
    print("arp_request")
    try:
        pk = pkt_in.packet_in_queue.get(block=True, timeout=3)
        #print(pk.packet.payload)
    except:
        print('NAO RECEBEU O PACOTE ###########################')
        
    else: # só executa se não tiver erro
        packet_bytes = pk.packet.payload
        #eth_packet = Ether(packet_bytes)
        
        #eth_packet.show() # pacote que entrou
        pktinfo = p4rtutil.decode_packet_in_metadata(cpm_packetin_id2data, pk.packet)
        
        #por_dst = read_register(sw, register=reg, idx=1)
        #ip_dst = decimal_to_ip(read_register(sw, register=reg, idx=2))

        port_dst = pktinfo['metadata']['operand0']
        ip_dst = pktinfo['metadata']['operand1']

        list = []
        list.append(ip_dst)
        list.append(packet_bytes) # lis[ip_dst da interface, pacote]
        queue_arp.append(list) # adiciona na lista o pacote

        #print(por_dst,decimal_to_ip(ip_dst))
        packet_out_request(sw, port_dst, ip_dst)   


def arp_reply(sw):
    print("arp_reply")
    try:
        pk = pkt_in.packet_in_queue.get(block=True, timeout=3)
        #print(pk.packet.payload)
    except:
        print('NAO RECEBEU O PACOTE ###########################')
        
    else: # só executa se não tiver erro
        pktinfo = p4rtutil.decode_packet_in_metadata(cpm_packetin_id2data, pk.packet)
        #pktinfo['payload'] # em bytes
        ip_src = pktinfo['metadata']['operand0']
        mac_src = pktinfo['metadata']['operand1']
        my_mac = pktinfo['metadata']['operand2']
        
        ip = f'{ip_src}/32'

        #mac = f'08:00:00:00:04:00 08:00:00:00:04:44' # esse valor vai ser descoberto pelo arp
        mac =  f'{my_mac} {mac_src}'
        table_add(sw,'arp_exact','arp_query', ip, mac, ptr=False, clean=5)
        for pkt_env in queue_arp:
            if pkt_env[0] == ip_src:
                pkt_out.payload = pkt_env[1]
                pkt_out.send()

def main():
    sw = connection()
    connection_sh()
    
    global pkt_out
    global pkt_in 
    pkt_out = sh.PacketOut()
    pkt_in = sh.PacketIn()
    
    Thd1 = Thread(target=table_clear, args=[sw,'arp_exact']) # Cria uma thread para rodar o backend
    Thd1.start()

    #reg = 'interface_ip'
    #init_reg(sw) // usar reg somente para sinal
    #init_table(sw)

    """
        Use a register:"controller_op" with the index equal a 0.
        op = 0: Nothing, wait!
        op = 1: Sem mac
        op = 2: Reply ARP para o roteador
        op = 3:
        op = 4:

    """

    while True:
        reg = 'controller_op'
        op = read_register(sw, register=reg, idx=0)
        if (op == 0):
            continue
        elif (op == 1):
            print('op = 1')
            write_register(sw,register=reg, idx=0, value=0)
            arp_request(sw) # roteador gera um request
        elif (op == 2):
            print('op = 2')
            write_register(sw,register=reg, idx=0, value=0)
            arp_reply(sw) #reply para o roteador
        elif(op == 11):
            print(" op = 11  ativo packet out")
            write_register(sw,register=reg, idx=0, value=22)
        elif (op == 4):
            print('op = 4 cpu_port')
        elif (op == 12):
            print('op = 12 request router')
        else:
            print('Unknown command')
        write_register(sw,register=reg, idx=0, value=0)
main()















#pp.stdin.close()
#red = pp.stdout.read()
#print(red)

# for i in range(50):
#     stdout_str = pp.stdout.readline().strip()
#     print(stdout_str)



# import subprocess

# def read_register(p, register, idx):

#     # Codifique a string de entrada como bytes
#     input_str = "register_read %s %d" % (register, idx)
#     input_bytes = input_str.encode('utf-8')

#     # Use 'input_bytes' como entrada e capture a saída padrão e de erro
#     stdout, stderr = p.communicate(input=input_bytes)

#     # Decodifique a saída de bytes de volta para uma string
#     stdout_str = stdout.decode('utf-8')

#     # Processar a saída, se necessário
#     #reg_val = [l for l in stdout_str.split('\n') if ' %s[%d]' % (register, idx) in l][0].split('= ', 1)[1]
#     #return int(reg_val)
#     return stdout_str


# # Crie o processo subprocesso
# thrift_port=9090
# pp = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# reg_val = read_register(pp, register='interface_ip', idx=1)
# reg_val2 = read_register(pp, register='interface_ip', idx=3)

# print(reg_val)
# print(' ')
# print(reg_val2)