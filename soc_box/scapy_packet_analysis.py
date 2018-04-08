#!/usr/bin/env python3

#
# Script to scrape relevant headers off packets
#

from scapy.all import *
import json
import requests
import argparse

# try/except chaning - probably not the best, but works
def handle_pkt(pkt):
    headers = {"packets":[{}]}

    try: # Ether packet
        headers["packets"][0]["source_MAC"] = pkt.src
        headers["packets"][0]["dest_MAC"] = pkt.dst

        try: # IP packet
            headers["packets"][0]["source_IP"] = pkt[IP].src
            headers["packets"][0]["dest_IP"] = pkt[IP].dst

            # Drop packets to private IP
            if pkt[IP].dst[0:3] == '10.' or pkt[IP].dst[0:7] == '192.168':
                print("Private destingation detected, dropping packet")
                return None

            try: # UDP packet
                headers["packets"][0]["source_port"] = pkt[UDP].sport
                headers["packets"][0]["dest_port"] = pkt[UDP].dport
            except:
                pass

            try: # TCP packet
                headers["packets"][0]["source_port"] = pkt[TCP].sport
                headers["packets"][0]["dest_port"] = pkt[TCP].dport
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
    parser.add_argument('--server', help='send header info to server', action='store_true')
    parser.add_argument('-v', '--verbose', help='print verbose output', action='store_true')
    parser.add_argument('pcap', help='pcap file to send', type=str, nargs='?')
    args=parser.parse_args()

    i = 0
    if args.pcap:
        with open(args.pcap) as FILE:
            packets = rdpcap(FILE)
            for pkt in packets:
                handle_pkt(pkt)
                i += 1
                if I < args.count:
                    break
    else:
        while i < args.count:

            pkt = sniff(count=1, store=1)
            header_info = handle_pkt(pkt[0])
            if header_info == None:
                continue
            else:
                if args.server:
                    print(requests.post("http://127.0.0.1:5000/check", json=header_info).json())
                if args.verbose:
                    print(header_info)
                i += 1

if __name__ == '__main__':
    main()
