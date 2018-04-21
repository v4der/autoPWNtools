#!/usr/bin/python

from colored import fg, attr
import netifaces
import getpass
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

def check_root():
	username = getpass.getuser()
	
	if username != "root":
		print("%s ERROR : YOU MUST BE A ROOT TO RUN THIS SCRIPT") % RED_ICON
		sys.exit(1)
	else:
		pass


def live_hosts(): # SCAN FOR LIVE HOSTS IN NETWORK
	all_network = GATEWAY + "/24"
	nm          = nmap.PortScanner()
	
	print("%s LIVE HOSTS SCANNING STARTED") % BLUE_ICON
	print("%s GATEWAY    : %s")             % (BLUE_ICON, GATEWAY)
	print("%s LIVE HOSTS : ")               % BLUE_ICON   
		
	nm.scan(hosts = all_network, arguments = "-sP")
	for host in nm.all_hosts():
		print("\t%s %s \t%s") % (GREEN_ICON, host, nm[host].hostname())


def help():
	print("""
%s ARGUMENTS:
1) --live-hosts                           = scan network for live hosts
2) --arp-poisoning <TARGET> <PLUGIN>      = arp poisoning attack
3) --evil-twin <NETWORK_SSID> <INTERFACE> = evil twin attack
4) --rediect-flash <target> <maleware>    = rediect to fake flash update site 

\t%s ARP POISONING ARGUMENTS:
\t -n = none
\t -p = pictures sniffer
\t -w = visited websites sniffer
	""") % (BLUE_ICON,
			BLUE_ICON)


def check_arguments():
	if sys.argv[1] == "--live-hosts":
		live_hosts()
		
	else:
		print("%s ERROR BAD ARGS") % RED_ICON
		help() 
	

def banner():
	print("""
######################################
#                                    #
#        %s--- [ c0bra ] ---%s           #
#                                    #
#     %sWirless Pentesting tool%s        #
#                                    #
#       %sCode by : Blackom412%s         #
#                                    #
#          %sVERSION : 0.0.1%s           #
#                                    #
######################################
""") % (fg(1)  , attr(0),
        fg(56) , attr(0),
        fg(239), attr(0),
        fg(125), attr(0))


#####################
### PROGRAM START ###
#####################

def main():
	banner()
	check_root()

	if len(sys.argv) < 2:
		help()
		
	else:
		check_arguments()

if __name__ == "__main__":
	main()
