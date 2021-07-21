#!/usr/bin/env python3
import requests
import scapy.all as scapy
from scapy.layers.l2 import ARP as ARP
from scapy.layers.l2 import Ether as Ether
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Enter the target ip or the ip range.")
    (options) = parser.parse_args()
    return options


def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=4, verbose=False)[0]
    clients_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc, "vendor": get_mac_details(mac_address=element[1].hwsrc)}
        clients_list.append(client_dict)

    return clients_list


def get_mac_details(mac_address):
    # We will use an API to get the vendor details
    url = "https://api.macvendors.com/"

    # Use get method to fetch details
    response = requests.get(url + mac_address)
    if response.status_code != 200:
        print("\ntrying to get vendors...")
    return response.content.decode()


def print_result(results_list):
    print("IP\t\t\tMAC Address \t\t\t\tVendor\n----------------------------------------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"] + "\t\t" + client["vendor"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
