#!/usr/bin/env python
import argparse
import scapy.all as scapy

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP range")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify target IP range, use --help for more info.")

    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    clients_list = []

    for element in answered_list:
        client = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client)

    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")

    for result in results_list:
        print(result["ip"] + "\t\t" + result["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
