#!/usr/bin/env python3

#
# Script to scrape relevant headers off packets
#

from scapy.all import *
import argparse

# try/except chaning - probably not the best, but works
def handle_pkt(pkt):
    headers = {}

    try: # Ether packet
        headers["source_MAC"] = pkt.src
        headers["dest_MAC"] = pkt.dst

        try: # IP packet
            headers["source_IP"] = pkt[IP].src
            headers["dest_IP"] = pkt[IP].dst

            try: # UDP packet
                headers["source_port"] = pkt[UDP].sport
                headers["dest_port"] = pkt[UDP].dport
            except:
                pass

            try: # TCP packet
                headers["source_port"] = pkt[TCP].sport
                headers["dest_port"] = pkt[TCP].dport
            except:
                pass

        except:
            pass

        return(headers)

    except:
        return("Error reading pkt")


def main():
    parser = argparse.ArgumentParser(description='Pulls relevant info out of Eth/IP/[TCP|UDP] headers for diagnostics')
    parser.add_argument('count', help='number of packets to sniff (because ctrl-C wont work', type=int)
    args=parser.parse_args()
    for i in range(0, args.count):

        pkt = sniff(count=1, store=1)
        header_info = handle_pkt(pkt[0])
        print("Packet info sniffed: {}\n".format(header_info))

if __name__ == '__main__':
    main()
