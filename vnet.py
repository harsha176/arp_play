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
import binascii

from util import *

from pytun import TunTapDevice, IFF_TAP

# Default vic config file
DEFAULT_CONFIG_FILE = os.path.join('resources', "vic.conf")

# Initialize logger
logFile = os.path.join('resources', 'logging.conf')
logging.config.fileConfig(logFile)
log = logging.getLogger('VNet')


# Writes frame over the tap
def write_frame(tap, frame):
	# Append first 4 bytes to a frame
	tap.write("\x00\x00\x00\x00" + str(frame))

# Reads frame over the tap
def read_frame(tap):
	# Ignore first 4 bytes of a packet
	return Ether(tap.read(1526)[4:])

# Handles IPv6 packets
def handle_ipv6(packet, tap):
	log.info("Ignoring IPv6 packet")

# This function handles arp packets for all tap drivers on the host.
def handle_arp(packet, tap):
	log.info("Received ARP request packet: ")

	arp_reply = packet.copy()
	arp_reply[ARP].op = 2
	arp_reply[ARP].hwsrc = "bb:bb:bb:bb:bb:bb"
	arp_reply[ARP].psrc =  packet[ARP].pdst
	arp_reply[ARP].pdst =  packet[ARP].psrc
	arp_reply[ARP].hwdst = '\x00\x11\x22\x33\x44\x55'

	arp_reply[Ether].dst = '\x00\x11\x22\x33\x44\x55'
	arp_reply[Ether].src = "bb:bb:bb:bb:bb:bb"

	# write the response on tap interface
	log.info("Sending ARP reply " + "to " + str(packet[ARP].psrc))
	write_frame(tap, arp_reply)
	

# Tunnel packets over other end point
def tunnel_packets(packet, tap):
	log.info("Tunneling packet over UDP on {0}: {1}".format(str(tap.addr), str(packet.summary())))
	
	# get other end UDP endpoint and send packets over there.

# Handle all packets over the vics
def handle_packets(taps):
	rrlist, wrlist, erlist = select.select(taps, [], [])

	# Log the contents which ever tap device is ready.
	for tap in rrlist:
		packet = read_frame(tap)
		# If it is an ARP request then send ARP reply
		if packet.haslayer(IPv6):
			handle_ipv6(packet, tap)
		elif packet.haslayer(ARP) and packet[ARP].op == 1:
			handle_arp(packet, tap)
		else:
			tunnel_packets(packet, tap)

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
		tap.hwaddr = '\x00\x11\x22\x33\x44\x55'
		tap.addr = ip
		tap.mtu = 1500
		tap.up()
		log.info("Tap device {0} is up with mac: {1}".format("vic-"+str(vic_id), binascii.hexlify(tap.hwaddr)))

		taps[ip] = tap
		
	
	tap_list = []
	for ip in taps.keys():
		tap_list.append(taps[ip])

	log.info("Waiting for packets on vics...")
	while True:
		handle_packets(tap_list)	

if __name__ == '__main__':
	initialize_vic()
