#!/usr/bin/env python3

import socket
from struct import unpack
from urllib.request import urlopen
from json import loads
from argparse import ArgumentParser

ECHO_REQUEST = b'\x08\x00\x0b\x27\xeb\xd8\x01\x00'
PRIVATE_NETWORKS = {
    ('10.0.0.0', '10.255.255.255'), 
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('127.0.0.0', '127.255.255.255')
}


def main():
    parser = ArgumentParser(description='Simple trace AS route utility')
    parser.add_argument('destination', type = str, help='Destination hostname')
    parser.add_argument('-hops', default = 30, type = int, help = 'Maximum number of hops')
    args = parser.parse_args()
    for message in traceroute(args.destination, args.hops):
        print(message)

def traceroute(destination, hops):
    destination = socket.gethostbyname(destination)
    current_address = None
    ttl = 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(5)
    while ttl != hops and current_address != destination:
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        sock.sendto(ECHO_REQUEST, (destination, 1))
        try:
            packet, ipPort = sock.recvfrom(1024)
            current_address = ipPort[0]
            message = current_address
            if is_public(current_address):
                message += get_location(current_address)
            yield message
            ttl += 1
        except socket.timeout:
            yield '*****'
            return
    sock.close()

def ip2long(ip):
    return unpack('!L', socket.inet_aton(ip))[0]

def is_public(ip):
    ip = ip2long(ip)
    for network in PRIVATE_NETWORKS:
        if ip2long(network[0]) <= ip <= ip2long(network[1]):
            return False
    return True

def get_location(ip):
    info = loads(urlopen('http://ipinfo.io/%s/json' % ip).read())
    message =  ' %s %s %s' % (info['country'], info['region'], info['city'])
    if 'org' in info:
        message += ' %s' % info['org']
    return message

if __name__ == '__main__':
    main()