from scapy.all import IP, ICMP

# Crie um pacote com cabeçalho IP seguido por um cabeçalho ICMP
packet = IP(src="192.168.1.1", dst="8.8.8.8") / ICMP()
print('a')
# Exiba apenas o cabeçalho IP
ip_header = packet[IP]
print(ip_header.show())