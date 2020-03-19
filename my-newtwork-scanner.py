#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_IP_from_user():
    parser = optparse.OptionParser()

    parser.add_option("-t", "--target", dest="target", help="specify a target IP or an IP RANGE")
    (options, arguments) = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a Target IP or a Range IP, use --help to see more info")
    return options





def scan(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]


    clients_list = [] #list
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("\n")
    print("------------------------------------------------------------")
    print("IP\t\t\tMAC Address")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

    print("------------------------------------------------------------")

options = get_IP_from_user()
scan_result = scan(options.target)
print_result(scan_result)
print("\n")