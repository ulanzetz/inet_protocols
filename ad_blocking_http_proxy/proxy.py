import socket
import socketserver
from http.server import SimpleHTTPRequestHandler, HTTPServer
from select import select
from time import sleep
from urllib.request import urlopen
from threading import Thread

PORT = 8080
BLACKLIST = {
    'reklama.e1.ru',
    'googleadservices.com',
    'doubleclick.net',
    'reklama.ngs.ru',
    'an.yandex.ru',
    'mc.yandex.ru',
    'mail.ru'
}
SOCKET_TIMEOUT = 0.5
SOCKET_MAX_IDLE = 10

class ProxyHandler(SimpleHTTPRequestHandler):
    def do_CONNECT(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
            path_parts = self.path.split(':')
            host, port = path_parts[0], int(path_parts[-1])
            try:
                if ProxyHandler.is_blacklisted(host):
                    self.send_error(423, 'Blacklisted host locked')
                    return
                client_sock.connect((host, port))
                self.send_response(200, 'Connection established')
                self.send_header('Proxy-agent', 'Test HTTP proxy')
                self.end_headers()
                socks = [self.connection, client_sock]
                self.socket_idle = 0
                while True:
                    input_ready, output_ready, exception_ready = select(socks, [], socks, 0.1)
                    if exception_ready:
                        return
                    if input_ready:
                        for item in input_ready:
                            data = item.recv(8192)
                            if data:
                                current_sock  = self.connection if item is client_sock else client_sock
                                current_sock.send(data)
                            elif self._socket_max_idle:
                                return
                    elif self._socket_max_idle:
                        return
            except socket.error:
                self.send_error(404, 'Not found')
            except ConnectionError:
                pass
            finally:
                self.connection.close()

    def do_GET(self):
        self.copyfile(urlopen(self.path), self.wfile)

    @property
    def _socket_max_idle(self):
        if self.socket_idle < SOCKET_MAX_IDLE:
            sleep(SOCKET_TIMEOUT)
            self.socket_idle += 1
            return False
        else:
            return True

    @staticmethod
    def is_blacklisted(host):
        for item in BLACKLIST:
            if item in host:
                return True
        return False


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass
        
if __name__ == '__main__':
    server = ThreadedTCPServer(('', PORT), ProxyHandler)
    thread = Thread(target=server.serve_forever)
    thread.start()