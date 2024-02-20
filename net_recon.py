#!/usr/bin/python3

# Program: Assignment 1 - Network Reconnaissance
# Author: KC
# Date: November 11, 2022
# Description: Allows user to passively or activly detect hosts on their network

from scapy.all import *
import sys
import os
# source: https://stackoverflow.com/questions/19359109/completely-clearing-the-terminal-window-using-python
clear = lambda : os.system('clear')


# ******************************************************************************
# Function: help()
# Description: Prints usage of command line arguments for net_recon.py
# ******************************************************************************
def help():
    print("Usage is: ./net_recon.py [-i or --iface] <interface name> [mode]")
    print("   Modes: [-a or --active] or [-p or --passive]")
    exit()


# ******************************************************************************
# Function: input_validation()
# Description: Input validation for number of args and arg flags
# ******************************************************************************
def input_validation():
    args = sys.argv
    n_args = len(args)
    iface = ""
    mode = 0

    # There are 3 arguments on command line
    if (n_args == 4): # includes script name as argument

        interface_flag = args[1]
        # Interface flag is the first argument after script name
        if (interface_flag == "-i" or interface_flag == "--iface"):
            # Interface name is the second argument
            iface = args[2]
        # Something other than interface flag is first argument
        else:
            help()

        mode_flag = args[3]
        # Active flag is third argument
        if (mode_flag == "-a" or mode_flag == "--active"):
            mode = "Active"

        # Passive flag is third argument
        elif (mode_flag == "-p" or mode_flag == "--passive"):
            mode = "Passive"

        # Neither passive nor active flag is third argument
        else:
            help()

    # There were not 3 arguments on command line
    else:
        help()

    cli_inputs = [iface, mode]
    return(cli_inputs)


# ******************************************************************************
# Function: print_table(iface, mode, hosts)
# Description: Print table with MAC, IP, and activity of hosts on a given
# interface and mode
# ******************************************************************************
def print_table(iface, mode, hosts):
    # Clear screen between function calls for live data view
    clear()
    # Source: https://www.geeksforgeeks.org/string-alignment-in-python-f-string/
    n_hosts = len(hosts)

    print("Interface:", f'{iface : <23}', \
        "Mode:", f'{mode : <23}', \
        "Found", f'{n_hosts : ^3}', "hosts")
    print('-'*80)
    print(f'{"MAC" : <34}', f'{"IP" : <29}', f'{"Host Activity" : <11}')
    print('-'*80)

    # Print based on mode
    if (mode == "Active"):
        for i in range(len(hosts)):
            print(f'{"?" : <34}', f'{hosts[i] : <29}')

    else:
        # Sort dictionary in descending order by number of occurrences
        # Source: https://www.freecodecamp.org/news/sort-dictionary-by-value-in-python/
        hosts_sorted_list = sorted(hosts.items(), key=lambda x: x[1][1], reverse=True)
        hosts = dict(hosts_sorted_list)
        # Print updated data in table
        for mac,data in hosts.items():
            print(f'{mac : <34}', f'{data[0] : <29}', f'{data[1] : <11}')


# ******************************************************************************
# Function: filter_packetse(iface, mode, mac_dict)
# Description: Packet handler for sniff() function, adds new hosts and updates
# existing host data in mac_dict
# ******************************************************************************
def filter_packets(iface, mode, mac_dict):
    def packet_handler(pkt):
        mac = pkt[Ether].src

        # If this is the first time seeing MAC addr, occurrence is 1
        occurrence = 1
        # Otherwise occurrence is incremented
        if (mac in mac_dict):
            occurrence = mac_dict[mac][1] + 1

        # Parse IP header if available
        ip = "?"
        if ("IP" in pkt):
            ip = pkt[IP].src

        # ARP traffic parsing
        try:
            arp = pkt[0][0][1]
            if (arp.op == 2):
                mac = arp.hwsrc
                ip = arp.psrc
        except:
            pass

        # Update mac_dict with new data and print table
        data = [ip, occurrence]
        mac_dict[mac] = data
        print_table(iface, mode, mac_dict)
    return packet_handler


# ******************************************************************************
# Function: passive_scan(iface, mode)
# Description: Runs a passive host scan on the given interface
# ******************************************************************************
def passive_scan(iface, mode):
    mac_dict = {}
    capture = sniff(iface=iface, prn=filter_packets(iface, mode, mac_dict))


# ******************************************************************************
# Function: active_scan(iface, mode)
# Description: Runs an active host scan on the given interface
# ******************************************************************************
def active_recon(iface, mode):
    # Fetch IP address of interface
    my_ip = get_if_addr(iface)
    my_ip = my_ip.split('.')
    my_ip = my_ip[0] +'.' + my_ip[1] + '.' + my_ip[2] + '.'

    # Send ICMP ping request to each host and record responses
    # Using CIDR /24 network addressing, so 255 hosts excluding broadcast addr
    cidr_24 = 255
    active_hosts = []
    for i in range(cidr_24):
        #ip_dst = '192.168.1.' + str(i)  # for testing on window-subsystem for linux with separate IP from interface
        ip_dst = my_ip + str(i)
        pkt = IP(dst=ip_dst)/ICMP()
        resp = sr1(pkt, iface=iface, timeout=0.1)

        # If there is no host at the ip_dest, the reponse is None, so continue
        if resp == None:
            pass
        # If there is a ping echo reply, save the IP
        else:
            ip_ping_reply = resp.getlayer("IP").src
            active_hosts.append(ip_ping_reply)

    # Print list of addresses with ICMP reply
    print_table(iface, mode, active_hosts)


# ******************************************************************************
# Function: main()
# Description: Driver function for net_recon.py
# ******************************************************************************
def main():
    cli_inputs = input_validation()
    iface = cli_inputs[0]
    mode = cli_inputs[1]

    # Active function finds available hosts by pinging local network
    if (mode == "Active"):
        active_recon(iface, mode)

    # Passive mode finds hosts and monitors their activity by sniffing network traffic
    if (mode == "Passive"):
        passive_scan(iface, mode)

main()
