# NetRecon
The net_recon.py script/tool enables users to detect hosts on their network, either passively or actively. It accepts two arguments: a network interface name and a mode indicator specifying active or passive scanning.

A lightweight network reconnaissance tool developed in Python using only scapy, sys, and os. This script supports both passive and active scanning of hosts on a local network and provides real-time insights into IP-MAC pairings and host activity.

This tool enables:
1. Passively scan for ARP replies to discover live hosts on the network.
2. Actively scan by broadcasting ARP requests across a /24 network.
3. View a dynamic, real-time display of hosts detected, including MAC, IP, and packet activity.
4. Efficiently identify active hosts and analyze local network behavior.

Usage:
      python3 net_recon.py -i <interface> -p     # Passive Scan
      python3 net_recon.py -i <interface> -a     # Active Scan
      python3 net_recon.py --help                # Usage instructions

Example:
      python3 net_recon.py -i eth0 -p
