#!/usr/bin/env python3

#
# Script to scrape relevant headers off packets
#

from scapy.all import *

# assumes that pkt is a Ether packet
def handle_pkt(pkt):
    try: 
        MAC_addr = pkt.src
        source_IP = pkt[IP].src
        dest_IP = pkt[IP].dst

        # TCP specific
        source_port = pkt[TCP].sport
        dest_port = pkt[TCP].dport
        return([MAC_addr, source_IP, dest_IP, source_port, dest_port])

    except: 
        return("Error reading pkt")


def main():
    for i in range(1, 5):
        pkt = sniff(count=1, store=1)
        pkt.show()
        header_info = handle_pkt(pkt)
        print("Packet info sniffed: {}\n".format(header_info))

if __name__ == '__main__':
    main()
