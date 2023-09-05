

import subprocess
import ipaddress

def connection(thrift_port = 9090):
    sw = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], \
                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sw.stdout.readline().strip() # Obtaining JSON from switch...
    sw.stdout.readline().strip() # Done
    sw.stdout.readline().strip() # Control utility for runtime P4 table manipulation
    return sw

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

def mac_to_decimal(mac_address, ptr=False):
    # Remove os dois pontos da string do endereço MAC, se houver
    mac_address = mac_address.replace(":", "")
    # Converte o endereço MAC hexadecimal em decimal
    decimal_value = int(mac_address, 16)
    if ptr:
        print("Valor do mac em decimal: ", decimal_value)
    return decimal_value

def decimal_to_mac(decimal_value, ptr=False):
    # Converte o valor decimal em uma string hexadecimal
    hex_value = format(decimal_value, '012X')  # 012X garante 12 dígitos hexadecimais
    # Adiciona os dois pontos para formatar o endereço MAC
    mac_address = ':'.join([hex_value[i:i+2] for i in range(0, len(hex_value), 2)])
    if ptr:
        print("end mac: ", mac_address)
    return mac_address

def table_add(sw, table, action, val_in, val_out, ptr=False): #table_add MyIngress.arp_exact arp_answer 10.0.11.10/32 => 00:11:22:33:44:55
    
    input_str = "table_add %s %s => %s %s \n" % (table, action, val_in, val_out)
    
    if ptr:
        print(input_str[0:-1])

    # Envie os dados de entrada para o processo e capture a saída
    sw.stdin.write(input_str)
    sw.stdin.flush()  # Certifique-se de que a entrada seja enviada imediatamente

def main():
    sw = connection()

    reg = 'interface_ip'

    reg_val = read_register(sw, register='interface_ip', idx=0, ptr=True)
    print(reg_val)

    write_register(sw,register=reg, idx=0, value=111, ptr = True)

    reg_val2 = read_register(sw, register='interface_ip', idx=0, ptr=True)
    print(reg_val2)

    """
        Use a register:"controller_op" with the index equal a 0.
        op = 0: Nothing, wait!
        op = 1: 
        op = 2:
        op = 3:
        op = 4:

    """

    while True:
        reg = 'controller_op'
        op = read_register(sw, register=reg, idx=0)
        if (op == 0):
            continue
        elif(op == 11):
            print(" op = 1")
            write_register(sw,register=reg, idx=0, value=22)
        elif (op == 2):
            print('op = 2')
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