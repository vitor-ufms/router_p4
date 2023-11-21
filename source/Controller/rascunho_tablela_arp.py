


# Criando uma tabela ARP vazia como um dicionário
tabela_arp = {}

# Adicionando entradas à tabela ARP
tabela_arp['192.168.1.1'] = '00:11:22:33:44:55'
tabela_arp['192.168.1.2'] = 'AA:BB:CC:DD:EE:FF'
tabela_arp['192.168.1.3'] = '11:22:33:44:55:66'

# Acessando entradas na tabela ARP
endereco_ip = '192.168.1.2'
if endereco_ip in tabela_arp:
    endereco_mac = tabela_arp[endereco_ip]
    print(f'O endereço MAC para {endereco_ip} é {endereco_mac}')
else:
    print(f'O endereço IP {endereco_ip} não foi encontrado na tabela ARP.')

# Removendo entradas da tabela ARP
del tabela_arp['192.168.1.1']

# Verificando o tamanho da tabela ARP
tamanho_tabela = len(tabela_arp)
print(f'O tamanho da tabela ARP é {tamanho_tabela}')

# Listando todos os registros na tabela ARP
for ip, mac in tabela_arp.items():
    print(f'Endereço IP: {ip}, Endereço MAC: {mac}')