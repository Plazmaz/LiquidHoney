import socket
import struct

from src.lh.parse_nmap_probes import ProbeFileParser
from src.lh.server.probe_server import ProbeServer


class ClientMock(object):
    def __init__(self, port, hostname, family=0):
        self.family = family
        self.port = port
        self.hostname = hostname
        self.data_recieved = None

    def getsockopt(self, level, option, buffersize=None):
        return struct.pack("!2xH4s8x", self.port, bytearray(self.hostname.encode('utf-8')))

    def sendto(self, data):
        self.send(data)

    def send(self, data):
        print("Got info: {}".format(data))
        self.data_recieved = data

    def recv(self, size):
        return "test"

    def recvfrom(self, size):
        return "test", None

    def close(self):
        pass


config_list = list(ProbeFileParser('test_directives.txt').iter_parse())
srv = ProbeServer(1234, 50, 3, False)
srv.add_from_config(22, config_list[0])


def get_data_for_port(port):
    address = '127.0.0.1'
    mock = ClientMock(port, address)
    srv.handle_client(mock, address)
    return mock.data_recieved

def get_data_for_udp_port(port):
    mock = ClientMock(port, None, socket.SOCK_DGRAM)
    srv.handle_client(mock, None)
    return mock.data_recieved

def test_resp():
    assert get_data_for_port(22) is not None