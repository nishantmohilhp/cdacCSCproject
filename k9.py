import scapy.all # packet capture module
from scapy_http import http # supplementing scapy module by providing http filter
from urllib.parse import unquote # to make url encoded text into string
 
# main class known as sniffing, the class file is k9.py
class sniffing:
    def __init__(self, interface, filter=""):
        self.sniffs(interface, filter) # filter is optional, default is empty string
        # filter can be "port 80", "tcp", "udp", "udp", "port 21" etc...
 
# The method that does the packet processing, by printing out packets sniff by scapy.
    def processing_packets(self, pkt):
        if pkt.haslayer(http.HTTPRequest): # http request filter
            if pkt.haslayer(scapy.all.Raw): # Raw data within the http packet which contains user and pwd.
                print(unquote(str(pkt[scapy.all.Raw]))) # print out the raw packet that has username and password.
 
# The method that calls scapy, this is the actual method that does the work.
    def sniffs(self, interface, filter):
        return scapy.all.sniff(iface=interface, store=0, prn=self.processing_packets, filter=filter)
