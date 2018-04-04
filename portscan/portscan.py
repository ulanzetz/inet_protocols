#!/usr/bin/env python3

import socket
from threading import Thread
from argparse import ArgumentParser
from re import match

def main():
	parser = ArgumentParser(description='UDP and TCP ports scanner')
	parser.add_argument('destination', type = str, help='Destination IPv4 or name')
	parser.add_argument('-s', '--start-port', default='1', type=int, help='Start port to scan')
	parser.add_argument('-e', '--end-port', default='100', type=int, help='End port to scan')
	parser.add_argument('-t', '--timeout', default=1, type=int, help='Timeout of response in seconds')
	parser.add_argument('-udp', '--udp-only', action='store_true', help='Scan only UDP ports')
	parser.add_argument('-tcp', '--tcp-only', action='store_true', help='Scan only TCP ports')
	args = parser.parse_args()


class PortScaner:

	DNS_TRANSACTION_ID = b'\x13\x37'

	DNS_PACKET = DNS_TRANSACTION_ID + \
				b'\x01\x00\x00\x01' + \
				b'\x00\x00\x00\x00\x00\x00' + \
				b'\x02\x65\x31\x02\x72\x75' + \
				b'\x00\x00\x01\x00\x01'

	TCP_PACKETS = {
		'HTTP' : b'\0',
		'SMTP' : b'\0',
		'DNS' : DNS_PACKET
		'POP3': b"AUTH"
	}

	UDP_PACKETS = {
		'SNTP' : b'\x1b' + 47 * b'\0'
		'DNS' : DNS_PACKET
	}

	PROTOCOL_CHECKER = {
		'HTTP': lambda packet: b'HTTP' in packet
		'POP3': lambda pakcet: packet.startwith(b'+')
		'DNS' : lambda packet: packet.startwith(DNS_TRANSACTION_ID)
		'SMTP' : lambda packet: match(b'[0-9]{3}', packet[:3])
		'SNTP' : lambda packet: PortScaner.__sntp_check(packet)
	}

	def __init__(self, dest, timeout):
		self.dest = dest
		socket.setdefaulttimeout(timeout)

	def scan_tcp_port(self, port):
		for prot, packet in TCP_PACKETS:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
				try:
					s.connect((dest, port))
				except socket.timeout:
					return None
				try:
					s.send(packet)
					if PROTOCOL_CHECKER[prot](s.recv(12)):
						return prot
				except:
					continue
		return 'Unknown service'

	def scan_udp_port(self, port):
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
			for prot, packet in UDP_PACKETS:
				s.sendto(packet, (dest, port))
				try:
					data, _ = s.recvfrom(48)
					

	@static_method
	def __sntp_check(packet):
		try:
			struct.unpack('!BBBb11I', pack)
			return True
		except:
			return False
