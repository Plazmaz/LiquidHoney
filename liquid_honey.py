import logging
import os
import requests
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

import click

from src.lh.parse_nmap_probes import ProbeFileParser
from src.lh.port_selector import PortSelector
from src.lh.server.probe_server import ProbeServer


@click.command()
@click.option('--stdout', is_flag=True, help='Enables stdout logging')
@click.option('--log-path', type=str, default='logs', help='Sets the directory to output logs to')
@click.option('--create-rules', default=False, is_flag=True, help='Attempt to create iptables rules (requires root!)')
def main(stdout, log_path, create_rules):
    logging.basicConfig(format='[%(levelname)s] [%(asctime)s] %(message)s',
                        filename='liquid-honey.log',
                        level=logging.DEBUG)
    rotator = TimedRotatingFileHandler(os.path.join(log_path, 'liquid-honey.log'),
                                       when="h",
                                       interval=1,
                                       backupCount=5)

    logging.getLogger().addHandler(rotator)
    if stdout:
        logging.getLogger().addHandler(logging.StreamHandler())

    download_nmap_version_db()

    configs = list(ProbeFileParser('nmap-service-probes').iter_parse())
    configs = PortSelector(configs).config_iterator()

    server = ProbeServer(create_rules)
    for port, config in configs:
        server.add_from_config(port, config)
    server.run()


# This is an attempt to avoid restrictions imposed by the GPL license.
# If maintainers of the nmap project feel this is non-compliant, please
# reach out, and I will be happy to work with you.
# This data is
def download_nmap_version_db():
    if os.path.isfile('nmap-service-probes'):
        return
    logging.info("'nmap-service-probes' not found. Downloading...")
    response = requests.get('https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes', stream=True)
    response.raise_for_status()
    with open('nmap-service-probes', 'wb') as file:
        for data in response.iter_content(8192):
            file.write(data)


if __name__ == '__main__':
    main()

