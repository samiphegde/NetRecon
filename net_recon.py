#!/usr/bin/python3

# Importing necessary libraries from the modules
from scapy.all import * # Provides tools for network scanning and packet manipulation
from sys import argv # Handles command-line arguments
from os import linesep, system # For newline characters

# Function to display the help information for correct usage of the tool
def help():
	print(	"",
		"./net_recon.py: Invalid options or arguments --",
		sys.argv[1:],
		"",
		"Usage:",
		"   ./net_recon.py <interface option> <iface> <mode option>",
		"",
		"Options:",
		"   <interface option>   ---> -i | --iface (Must be specified at all times)",
		"   <iface>   ---> Network interface name",
		"   <mode option>   ---> -a | --active | -p | --passive",
		"",
		sep=linesep)
	exit() # Exits the program after displaying the usage information

# Improved display function for better ouput readability
def imprvd_display(intface, mode, hosts):
	system('clear') # Clears the console to create the illusion of a single updating table
	detected_hosts = len(hosts) # Number of detected hosts
	print("","",sep=linesep)
	print(f"Interface: {intface.ljust(19)} Mode: {mode.ljust(19)} Found {detected_hosts} hosts")
	print("-"*72)
	# Determines display headers based on active or passive mode
	print("MAC".ljust(30), "IP".ljust(25), "Host Activity" if (argv[3] == mode_options[2] or argv[3] == mode_options[3]) else "")
	print("-"*72)
	# Checks if the user provided argument is for passive scan
	if (argv[3] == mode_options[2] or argv[3] == mode_options[3]):
		# Sorts hosts by packet count and prints each entry for passive scan
		for i in sorted(hosts.items(), key = lambda x: x[1]['count'], reverse = True):
			print(i[1]['mac'].ljust(30), i[0].ljust(25), str(i[1]['count']))
	else:
		# Prints each entry for active scan
		for i in hosts.items():
			print(i[1]['mac'].ljust(30), i[0].ljust(25))


# Active scan function when user specifies the '-a' or '--active' flag as argument
def active_scan(intface):
	def arp_req_pkts(ans_list):
		hosts = {} # Unique IP addresses dictionary
		# Checks if any ARP responses were recived
		if ans_list:
			# Loops through each response received
			for i in ans_list:
				if i[1].psrc not in hosts:
					hosts[i[1].psrc] = {'mac': i[1].hwsrc} # Adds unique entries to the dictionary
					imprvd_display(intface,"Active",hosts)  # Calls improved display function with active mode details
		else:
			imprvd_display(intface,"Active",hosts) # Calls improved display function if no ARP replies received
			print("","No ARP reply received",sep=linesep)

	ip_addr = get_if_addr(intface) # Extracts IP address of the specified interface
	net_range = f"{ip_addr}/24" # Defines subnet mask
	ether_header = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x0806) #Ethernet braodcast frame for ARP
	arp_req_header = ARP(op=1, pdst=net_range) # ARP request packet for the network range
	arp_req_pkt = ether_header/arp_req_header # Combines Ether and ARP headers into one packet
	try:
		ans_list = srp(arp_req_pkt, iface= intface, verbose=0, timeout=2)[0] # Send ARP requests and captures responses
		arp_req_pkts(ans_list) # Function call to process the ARP responses received
	except KeyboardInterrupt:
		print("","Active scan interrupted and stopped","",sep=linesep)
		exit() # Graceful exit on user interrupt

# Passive scan function - when user specifies the '-p' or '--passive' flag as argument
def passive_scan(intface):
	def arp_reply_pkts(pkt):
		# Checks if the packet is an ARP reply
		if pkt.haslayer(ARP) and pkt[ARP].op == 2:
			if pkt[ARP].psrc in hosts:
				hosts[pkt[ARP].psrc]['count'] += 1 # Updates count if host is already detected
			else:
				hosts[pkt[ARP].psrc] = {'mac': pkt[ARP].hwsrc, 'count':1} # Adds new host entry if detected for the first time
		# If packet has other layers but is from a known ARP host, increment host activity count
		elif pkt.haslayer(IP) and pkt[IP].src in hosts:
			hosts[pkt[IP].src]['count'] += 1 # Increments host activity count
		imprvd_display(intface,"Passive",hosts) # Calls improved display function with passive mode details


	hosts = {} # Nested dictionary that stores host's IP addresses with their respective MAC addresses and packet counts
	print(f"Listening for ARP traffic on the interface: {intface}") # Passive scan start
	try:
		sniff(iface=intface, store=0, count=0, prn=arp_reply_pkts) # Sniffs traffic and calls arp_reply_pkts function for each packet
	except KeyboardInterrupt:
		print("","Passive scan interrupted and stopped","",sep=linesep)
		exit() # Graceful exit on user interrupt

# Main function - Handles input arguments and starts the scan
def main():
	interface_options = ["-i", "--iface"] # Valid flags or options for interface
	global mode_options # Declared as global variable
	mode_options = ["-a", "--active", "-p", "--passive"] # Valid flags or options for active and passive mode
	# Validates argument count and checks if the flags or options are valid
	if ((len(argv) == 4) and (argv[1] in interface_options) and (argv[3] in mode_options)):
		try:
			iface = argv[2] # Extracts interface name
			# Starts active or passive scan based on mode flag
			if (argv[3] == mode_options[0] or argv[3] == mode_options[1]):
				active_scan(iface) # Calls active scan function
			elif (argv[3] == mode_options[2] or argv[3] == mode_options[3]):
				passive_scan(iface) # Calls passive flag function
		except Exception as e:
			print(e) # Prints the error
			help() # Calls help if the user provided arguments are invalid
	else:
		help() # Calls help if the user provided arguments are invalid


# Main guard - TO ensure that main function runs only when executed as a script
if __name__ == "__main__":
	main()
