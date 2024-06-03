#!/usr/bin/env python3

from scapy.all import *
import argparse

# This program recalculate checksum for pcap file


def del_chksum(file_in="*.pcap", file_out="*.pcap"):
	# Read file pcap
	scapy_cap = rdpcap(file_in)
	for pkt in scapy_cap:
		# Recalculate IP length, IP checksum, TCP checksum and UDP checksum header if it have in packet
		try:
			del pkt[IP].len
			del pkt[IP].chksum
			try:
				del pkt[TCP].chksum
			except:
				pass
			try:
				del pkt[UDP].chksum
			except:
				pass
		except:
			pass
	# Write file pcap after recalculate
	wrpcap(file_out, scapy_cap)

if __name__ == "__main__":
	try:
		file_in = None
		file_out = None
		parser = argparse.ArgumentParser()
		parser.add_argument("-i", "--input", help = "Incorrect checksum .pcap file input")
		parser.add_argument("-o", "--output", help = "Correct checksum .pcap file output")
		args = parser.parse_args()
		# -i argument to file_in
		if args.input:
			file_in = args.input
		# -o argument to file_out
		if args.output:
			file_out = args.output
		# if only have -i argument file_out = file_in
		if file_out == None:
			file_out = file_in
		del_chksum(file_in, file_out)
	except Exception as e:
		print(e)
		
