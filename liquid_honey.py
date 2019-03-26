import logging
import os
import shutil
import sys

import requests
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

import click

from src.lh.parse_nmap_probes import ProbeFileParser
from src.lh.port_selector import PortSelector
from src.lh.server.probe_server import ProbeServer


@click.command()
@click.option('--stdout', is_flag=True, help='Enables stdout logging (Default false)')
@click.option('--log-path', type=str, default='logs', help='Sets the directory to output logs to (Default "logs")')
@click.option('--listen-port', type=int, default=11337, help='Set a port to forward traffic to. '
                                                             'This should be a service you aren\'t spoofing. '
                                                             '(Default 1137)')
@click.option('--create-rules', default=False, is_flag=True, help='Attempt to create iptables rules (requires root!)')
def main(stdout, log_path, listen_port, create_rules):
    logging.basicConfig(format='[%(levelname)s] [%(asctime)s] %(message)s',
                        filename='liquid-honey.log',
                        level=logging.DEBUG)
    # Backups every 6 hrs, keeps up to 42 (7 days) worth of logs.
    rotator = TimedRotatingFileHandler(os.path.join(log_path, 'liquid-honey.log'),
                                       when="h",
                                       interval=6,
                                       backupCount=42)

    logging.getLogger().addHandler(rotator)
    if stdout:
        logging.getLogger().addHandler(logging.StreamHandler())

    check_nmap_db()

    configs = list(ProbeFileParser('nmap-service-probes').iter_parse())
    configs = PortSelector(configs).config_iterator()

    server = ProbeServer(listen_port, create_rules)
    for port, config in configs:
        server.add_from_config(port, config)
    server.run()


def check_nmap_db():
    if os.path.isfile('nmap-service-probes'):
        return

    if os.path.isfile('/usr/share/nmap/nmap-service-probes'):
        shutil.copy('/usr/share/nmap/nmap-service-probes', 'nmap-service-probes')
    elif os.path.isfile('/usr/local/share/nmap/nmap-service-probes'):
        shutil.copy('/usr/local/share/nmap/nmap-service-probes', 'nmap-service-probes')

    if not os.path.isfile('nmap-service-probes'):
        print("'nmap-service-probes' not found. "
              "Please download it or install nmap (see README)")
        sys.exit(1)

if __name__ == '__main__':
    main()
