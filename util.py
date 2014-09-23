#!/usr/bin/env python

#
# Utility functions
#

# Converts mac address to binary
def mac2binary(mac):
	if ':' in mac:
		delim = ':'
	elif '-' in mac:
		delim = '-'
	else:
		raise error("Invalid mac: "+str(mac))

	return bin(int(mac.replace(delim, ''), 16))

def binary2mac(mac):
	t_mac = int(mac, 2)
	bytes = []
	while t_mac > 0:
		bytes.append(str('%2x'%(t_mac & 255)))
		t_mac = t_mac >> 8

	return ":".join(reversed(bytes))
