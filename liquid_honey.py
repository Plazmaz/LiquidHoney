import logging
import os
import shutil
import sys
from logging.handlers import TimedRotatingFileHandler

import click
from xeger import Xeger

from src.lh.config import LHConfig
from src.lh.parse_nmap_probes import ProbeFileParser
from src.lh.port_selector import PortSelector
from src.lh.server.probe_server import ProbeServer


@click.command()
@click.option('--stdout', is_flag=True, help='Forcefully enables stdout logging')
@click.option('--log-path', type=str, default=None, help='Overrides the directory to output logs to')
@click.option('--listen-port', type=int, default=None, help='Override the port to forward traffic to. '
                                                            'This should be a service you aren\'t spoofing.')
@click.option('--create-rules', default=False, required=False, is_flag=True,
              help='Attempts to create iptables rules (requires root!)')
def main(stdout, log_path, listen_port, create_rules):
    conf = LHConfig('config.yml')

    stdout = stdout or not conf.file_only
    log_path = log_path or conf.log_path
    listen_port = listen_port or conf.listen_port

    logging.basicConfig(format='[%(levelname)s] [%(asctime)s] %(message)s',
                        filename=os.path.join(log_path, 'liquid-honey.log'),
                        level=logging.DEBUG)
    # Backups every 6 hrs, keeps up to 42 (7 days) worth of logs.
    rotator = TimedRotatingFileHandler(os.path.join(log_path, 'liquid-honey.log'),
                                       when="h",
                                       interval=conf.log_rollover,
                                       backupCount=conf.max_log_files)

    logging.getLogger().addHandler(rotator)

    if stdout:
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

    check_nmap_db(conf.service_probes_location)
    probes = list(ProbeFileParser(conf).iter_parse())
    probes = PortSelector(probes).config_iterator()

    server = ProbeServer(listen_port, conf.max_ports_per_service, conf.max_replies, create_rules)

    for port, config in probes:
        server.add_from_config(port, config)

    server.run()


def check_nmap_db(filename):
    if os.path.isfile(filename):
        return

    if os.path.isfile('/usr/share/nmap/nmap-service-probes'):
        shutil.copy('/usr/share/nmap/nmap-service-probes', filename)
    elif os.path.isfile('/usr/local/share/nmap/nmap-service-probes'):
        shutil.copy('/usr/local/share/nmap/nmap-service-probes', filename)

    if not os.path.isfile(filename):
        logging.error("File '%s' not found. "
                      "Please download nmap-service-probes or install nmap (see README)", filename)
        sys.exit(1)


if __name__ == '__main__':
    main()
