#!/usr/bin/env python3

import socket
from sys import stdin
from ssl import wrap_socket
from configparser import ConfigParser
from base64 import b64decode
from re import compile, IGNORECASE
from pathlib import Path

class POP3Client:
	__MESSAGE_END_CHUNK = b'.\r\n'
	__HEADERS_END_CHUNK = b'\r\n'
	__BASE64_UTF_8_RE = compile('=\?utf-8\?b\?([^\?]+)\?=', flags=IGNORECASE)

	def __init__(self, server, account, buffer_size=1024):
		self.buffer_size = buffer_size
		self.__log = []
		self.__sock = wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
		self.__sock.settimeout(float(server['Timeout']))
		self.__sock.connect((server['Address'], int(server['Port'])))
		self.__log_msg(self.__sock.recv(1024).decode())
		self.__log_msg(self.__command_exchage('USER ' + account['Login']))
		self.__log_msg(self.__command_exchage('PASS ' + account['Password']))

	def execute_user_cmd(self, user_cmd):
		if user_cmd.startswith('_'):
			return None
		args = list(map(lambda s: s.strip(), user_cmd.split(' ')))
		return getattr(self, args[0])(*args[1:])

	def msg(self, msg_id):
		self.msg_id = msg_id
		self.__headers_gen = self.__get_headers_gen()
		self.__headers = {}
		return f'Message {msg_id} was chosen'

	def header(self, header_name):
		if header_name in self.__headers:
			return self.__headers[header_name]
		for h, v in self.__headers_gen:
			if h == header_name:
				return v

	def headers(self):
		self.__headers.update({h : v for h, v in self.__headers_gen})
		return '\n'.join(f'{h} : {v}' for h, v in self.__headers.items())

	def quit(self):
		self.__log_msg(self.__command_exchage('QUIT'))
		return f'Quited'

	def log(self):
		return 'Log:\n' + '\n'.join(self.__log)

	def all_msg(self):
		self.headers()
		msg_body = b''.join(
			self.__recv_cmd_chunks(
				f'RETR {self.msg_id}', 
				self.__headers_len
			)
		)
		if self.__headers['Content-Type'].startswith('multipart/mixed'):
			def delete_quotes_if_exists(str):
				if str[0] == str[-1] == '"':
					str = str[1:-1]
				return str

			boundary = delete_quotes_if_exists(
				self.__headers['Content-Type'].split('=')[1]
			).encode()

			out_folder = f'./msg{self.msg_id}'
			Path(out_folder).mkdir(parents=True, exist_ok=True)
			out_filenames = set() 

			parts = msg_body.split(b'--' + boundary)[:-1]
			for part in parts:
				headers, body = part.split(b'\r\n\r\n', 1)
				if b'text/plain' in headers:
					out_filename = f'{out_folder}/text.txt'
					with open(out_filename, 'w', encoding='utf-8') as f:
						f.write(body.decode())
					out_filenames.add(out_filename)
				elif b'base64' in headers:
					body = body.decode().strip()
					filename = delete_quotes_if_exists(headers.split(b'name=')[1].split(b'\r')[0].decode())
					out_filename = f'{out_folder}/{filename}'
					with open(out_filename, 'wb') as f:
						f.write(b64decode(body))
					out_filenames.add(out_filename)
				else:
					return 'Unsupportable encoding'
		return 'Your message was saved in\n' + '\n'.join(out_filenames)


	def __get_headers_gen(self):
		current_header = None
		chunks = self.__recv_cmd_chunks(f'TOP {self.msg_id} 1')
		self.__headers_len = len(chunks)
		for chunk in chunks:
			if chunk == POP3Client.__HEADERS_END_CHUNK:
				break
			line = chunk.decode()
			if line.startswith('\t'):
				current_value += line
			else:
				next_header, next_value = list(map(lambda s: s.strip(), line.split(':', 1)))
				if current_header is not None and next != current_header:
					current_value = POP3Client.__decode_all_b64_utf8(current_value)
					self.__headers[current_header] = current_value
					yield current_header, current_value
				current_header, current_value = next_header, next_value

	@staticmethod
	def __decode_all_b64_utf8(str):
		return POP3Client.__BASE64_UTF_8_RE.sub(lambda match: b64decode(match.group(1)).decode(), str)

	def __recv_cmd_chunks(self, cmd, start = 0):
		self.__log_msg(self.__command_exchage(cmd))
		chunks, index = [], 0
		while True:
			chunk = self.__sock.recv(self.buffer_size)
			if chunk == POP3Client.__MESSAGE_END_CHUNK:
				break
			if index >= start:
				chunks.append(chunk)
			else:
				index += 1
		return chunks

	def __command_exchage(self, cmd):
		self.__sock.send(cmd.encode() + b'\n')
		return self.__sock.recv(self.buffer_size).decode()

	def __log_msg(self, msg):
		self.__log.append(msg)

	def __del__(self):
		self.__sock.close()


if __name__ == '__main__':
	parser = ConfigParser(allow_no_value=True)
	with open('config.cfg', 'r', encoding='utf-8') as f:
		parser.readfp(f)
	client = POP3Client(parser['Server'], parser['Account'])
	while True:
		cmd = stdin.readline()[:-1]
		try:
			print(client.execute_user_cmd(cmd) + '\n')
			if cmd == 'quit':
				break
		except KeyboardInterrupt:
			print(client.execute_user_cmd('quit') + '\n')
			break
