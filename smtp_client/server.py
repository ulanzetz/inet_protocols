import socket
from base64 import b64encode
from ssl import wrap_socket
from configparser import ConfigParser

parser = ConfigParser(allow_no_value = True)
with open('config.cfg', 'r', encoding='utf-8') as f:
	parser.readfp(f)

msg = parser['Message']
account = parser['Account']

with open(msg['Text'], 'r', encoding='utf-8') as f:
	text = f.read()

attachments = ''

boundary = msg['Boundary']

for attachment in msg['Attachments'].split('\n')[1:]:
	attachment = attachment.split(',')
	filename = attachment[0].strip()
	mime_type = attachment[1].strip()
	with open(filename, 'rb') as f:
		file = b64encode(f.read())
		attachments += (f'Content-Disposition: attachment; filename="{filename}"\n'
		'Content-Transfer-Encoding: base64\n'
		f'Content-Type: {mime_type}; name="{filename}"\n\n'
		) + file.decode() + f'\n--{boundary}'

login = account['Login']
recipients = ','.join(parser['Recipients'])
subject = msg['Subject']

if not all(ord(c) < 128 for c in subject):
	subject = f'=?utf-8?B?{b64encode(subject.encode()).decode()}?='

message = (
	f'From: {login}\n'
	f'To: {recipients}\n'
	f'Subject: {subject}\n'
	'MIME-Version: 1.0\n'
	f'Content-Type: multipart/mixed; boundary="{boundary}"\n\n'
	f'--{boundary}\n'
	'Content-Type: text/plain; charset=utf-8\n'
	'Content-Transfer-Encoding: 8bit\n\n'
	f'{text}\n'
	f'--{boundary}\n'
	f'{attachments}--\n.'
	)

def command_exchage(sock, cmd, buffer=1024):
	sock.send(cmd + b'\n')
	return sock.recv(buffer).decode()

login = login.encode()
password = account['Password'].encode()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
	sock = wrap_socket(sock)
	server = parser['Server']
	sock.settimeout(float(server['Timeout']))
	sock.connect((server['Address'], int(server['Port'])))
	print(command_exchage(sock, b'EHLO test'))
	print(command_exchage(sock, b'AUTH LOGIN'))
	print(command_exchage(sock, b64encode(login)))
	print(command_exchage(sock, b64encode(password)))
	print(command_exchage(sock, b'MAIL FROM: ' + login))
	for recipient in parser['Recipients']:
		print(command_exchage(sock, b'RCPT TO: ' + recipient.encode()))
	print(command_exchage(sock, b'DATA'))
	print(command_exchage(sock, message.encode()))
	print('Message sent')

