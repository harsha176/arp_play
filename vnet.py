#!/usr/bin/env python

#
# Configures a virtual interface based on the config file.
#

import os
import yaml

import logging
import logging.config 
from scapy.all import *
import select

from pytun import TunTapDevice, IFF_TAP

# Default vic config file
DEFAULT_CONFIG_FILE = os.path.join('resources', "vic.conf")

# Initialize logger
logFile = os.path.join('resources', 'logging.conf')
logging.config.fileConfig(logFile)
log = logging.getLogger('VNet')


# This function handles arp packets for all tap drivers on the host.
def handle_arp(packet, tap):
	arp_reply = packet
	arp_reply[ARP].op = 2
	arp_reply[ARP].hwsrc = "bb:bb:bb:bb:bb:bb"
	arp_reply[ARP].psrc = packet[ARP].pdst
	arp_reply[Ether].dst = "ff:ff:ff:ff:ff:ff"

	# write the response on tap interface
	log.info("Sending ARP reply to " + str(packet[ARP].psrc))
	tap.write("\x00\x00\x00\x00" + str(arp_reply))
	

# Initializes VIC based on vic config
def initialize_vic():
	# Read config file and get parameters.
	log.info ("Reading vic config from "+ DEFAULT_CONFIG_FILE)
	f = open(DEFAULT_CONFIG_FILE, "r")
	vic_config = yaml.load(f)
	f.close()

	# Configure each vic
	vic_id = 0
	taps = {}
	for vic in vic_config:
		log.info ("Configuring vic id: "+ str(vic_id))
 		ip = vic['ip']
		log.info("vic_ip: "+ ip)
		mac = vic['mac']
		log.info("vic_mac: "+ mac)
		
		# Create virtual interface
		tap = TunTapDevice(name="vic-"+str(vic_id), flags=IFF_TAP)
		tap.addr = ip
		#tap.mtu = 1500
		tap.up()
		log.info("Tap device {0} is up".format("vic-"+str(vic_id)))

		taps[ip] = tap
		
	
	log.info("Waiting for packets on vics...")
	rlist = []
	for ip in taps.keys():
		rlist.append(taps[ip])

	while True:
		try:
			rrlist, wrlist, erlist = select.select(rlist, [], [])

			# Log the contents which ever tap device is ready.
			for tap in rrlist:
				packet = Ether(tap.read(1526)[4:])
				# If it is an ARP request then send ARP reply
				if packet.haslayer(IPv6):
					log.info("Ignoring IPv6 packet")
				elif packet.haslayer(ARP) and packet[ARP].op == 1:
					log.info("Received ARP request packet: ")
					handle_arp(packet, tap)
				else:
					log.info("Tunneling packet over UDP on {0}: {1}".format(str(tap.addr), str(packet.summary())))
		except Exception, e:
			log.error("Encountered error: " + e.message)
			break
		

if __name__ == '__main__':
	initialize_vic()
