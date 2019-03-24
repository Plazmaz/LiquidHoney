from ssl import SSLContext, PROTOCOL_TLS_SERVER
import logging
import select
import socket
import threading
import traceback
from abc import ABC
from random import SystemRandom

import exrex

from src.lh.server.exception import SocketException
from src.lh.service_directives import SoftMatch

CLAIMED_PORTS = []


class ProbeServer(ABC):
    MAX_PORTS_PER_SERVER = 100
    BUFFER_SIZE = 256
    socket_threads = []
    ssl_context = None

    def __init__(self):
        self.sockets = []
        self.ports = []
        self.fingerprint_to_probes = {}
        self.port_options = {}
        self.match_idx = {}
        self.ssl = None
        self.rand = SystemRandom()

    def add_from_config(self, port, config, hostname):
        self.ssl_context = SSLContext(PROTOCOL_TLS_SERVER)
        if config.has_directive('sslport'):
            self.ssl_context.load_cert_chain('cacert.pem', 'private.key')
            ssl_ports = config.get_directives('sslport').ports
            ssl = port in ssl_ports
        else:
            ssl = False
        self.ssl = ssl

        probe_directive = config.get_directives('probe')[0]
        is_udp = probe_directive.protocol == 'UDP'

        matches = config.get_directives('match')
        if not matches:
            logging.warning("Match directive not found. Skipping!")
            return False

        self.add_server(port, is_udp, ssl, hostname)
        CLAIMED_PORTS.append(port)
        self.port_options[port] = matches
        self.match_idx[port] = 0
        self.ports.append(port)

    def add_server(self, port, udp, ssl, hostname):
        if udp:
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if ssl:
            server = self.ssl_context.wrap_socket(server, server_hostname=hostname)

        logging.info("Listening on {} port {}".format('UDP' if udp else 'TCP', port))

        try:
            server.bind(("0.0.0.0", port))
        except OSError as e:
            logging.info('Unable to bind to port {}: {}'.format(port, e))
            return

        logging.info("Bound to port {}".format(port))
        if not udp:
            server.listen(1)
        self.socket_threads.append(server)

    def run(self):
        # TODO: Multithread this
        while True:
            readable_streams, _, _ = select.select(self.socket_threads, [], [])
            server = readable_streams[0]
            try:
                connection, address = server.accept()
            except OSError:
                continue
            except:
                traceback.print_exc()
                continue

            threading.Thread(target=self.handle_client, args=(connection, address)).start()

    def handle_client(self, client, address):
        is_udp = client.family == socket.SOCK_DGRAM
        while True:
            try:
                if is_udp:
                    data, _ = client.recvfrom(self.BUFFER_SIZE)
                else:
                    data = client.recv(self.BUFFER_SIZE)
                if not data:
                    raise SocketException('Client {} disconnected.'.format(address))

                port = client.getsockname()[1]
                logging.info("[%s:%s] -> S(%d): %s %s", address[0], address[1], port, str(data), '(SSL)' if self.ssl else '')

                matches = self.port_options[port]
                match = self.rand.choice(matches)
                pattern = match.pattern
                if isinstance(match, SoftMatch):
                    response = exrex.getone(pattern, limit=10e3)
                else:
                    response = exrex.getone(pattern, limit=10e3)

                response = response.encode('utf-8').decode()
                if is_udp:
                    client.sendto(response.encode(), address)
                    # print(response.encode())
                else:
                    client.send(response.encode())
            except SocketException:
                client.close()
                return False

            except Exception:
                logging.info("Encountered unknown when handling data from %s.", address)
                client.close()
                traceback.print_exc()
                return False
