#!/usr/bin/env python3

import struct
import socket

class DNSServer:

    def __init__(self, port, forwarder):
        self.port = port
        self.forwarder = forwarder
        self.cache = {}

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('', self.port))
            while True:
                try:
                    data, address = s.recvfrom(1024)
                    s.sendto(self.make_answer(data), address)
                except KeyboardInterrupt:
                    print('Closing server')
                    return
                except Exception as e:
                    print(e)
                    continue

    def make_answer(self, bytes):
        msg = DNSMessage.parse_message(bytes)
        for question in msg.questions:
            if not question in self.cache:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(1)
                    s.connect(self.forwarder)
                    s.send(bytes)
                    data = s.recv(1024)
                    self.cache.update(DNSMessage.parse_message(data).answers)
                    return data
            if question.q_type == 6:
                msg.authority[question] = self.cache[question]
                msg.authority_RR += 1
            else:
                msg.answers[question] = self.cache[question]
                msg.answers_RR += 1
            print('From cache')
        msg.flags = 0x8580
        return msg.to_bytes()

class DNSMessage:

    @staticmethod
    def parse_message(bytes):
        msg = DNSMessage()
        (msg.id, msg.flags, msg.questions_RR, 
            msg.answers_RR, msg.authority_RR, msg.additonal_RR
        ) = struct.unpack_from('!HHHHHH', bytes, 0)
        msg.questions = []
        msg.answers = {}
        msg.authority = {}
        offset = 12
        for i in range(msg.questions_RR):
            query, offset = DNSQuery.parse_query(bytes, offset)
            msg.questions.append(query)
        for i in range(msg.answers_RR + msg.authority_RR):
            query, offset = DNSQuery.parse_query(bytes, offset)
            record, offset = DNSRecord.parse_record(bytes, offset)
            msg.answers[query] = record
        return msg

    def to_bytes(self):
        bytes = struct.pack('!HHHHHH',
            self.id,
            self.flags,
            self.questions_RR,
            self.answers_RR,
            self.authority_RR,
            self.additonal_RR
            )
        for question in self.questions:
            bytes += question.to_bytes()
        for question, answer in self.answers.items() | self.authority.items():
            bytes += question.to_bytes()
            bytes += answer.to_bytes()
        return bytes

class DNSQuery:

    @staticmethod
    def parse_query(bytes, offset):
        query = DNSQuery()
        query.url, offset = DNSQuery.__parse_url(bytes, offset)
        query.q_type, offset = parse_short(bytes, offset)
        query.q_class, offset = parse_short(bytes, offset)
        return (query, offset)

    def to_bytes(self):
        return DNSQuery.__url_to_bytes(self.url) + struct.pack('!HH', self.q_type, self.q_class)

    def __hash__(self):
        return hash(self.url) ** hash(self.q_type) ** hash(self.q_class)

    def __eq__(x, y):
        return x.url == y.url and x.q_type == y.q_type and x.q_class == y.q_class

    @staticmethod
    def __parse_url(bytes, offset, recursive = False):
        url = ''
        while bytes[offset] != 0 and bytes[offset] < 0x80: 
            for i in range(1, bytes[offset] + 1):
                url += chr(bytes[offset + i])
            url += '.'
            offset += bytes[offset] + 1
        if bytes[offset] >= 0x80:
            end_offset = parse_short(bytes, offset)[0] & 0x1fff
            url += DNSQuery.__parse_url(bytes, end_offset, True)[0]
            offset += 1
        if not recursive:
            url = url[:-1]
        return (url, offset + 1)

    @staticmethod
    def __url_to_bytes(url):
        bytes = b''
        for part in url.split('.')[:-1]:
            bytes += struct.pack('B', len(part))
            bytes += part.encode(encoding = 'utf-8')
        return bytes + b'\0'

class DNSRecord:

    @staticmethod
    def parse_record(bytes, offset):
        record = DNSRecord()
        record.ttl, offset = parse_long(bytes, offset)
        length, offset = parse_short(bytes, offset)
        record.info = bytes[offset : offset + length]
        return(record, offset + length)

    def to_bytes(self):
        return struct.pack('!IH', self.ttl, len(self.info)) + self.info

def parse_short(bytes, offset):
    return (struct.unpack_from('!H', bytes, offset)[0], offset + 2)

def parse_long(bytes, offset):
    return (struct.unpack_from('!I', bytes, offset)[0], offset + 4)

if __name__ == '__main__':
    DNSServer(53, ('8.8.8.8', 53)).start()
