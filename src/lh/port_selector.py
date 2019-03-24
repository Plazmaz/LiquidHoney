import logging

from src.lh.parse_nmap_probes import ProbeFileParser


class PortSelector(object):
    """
    Selects the optimal service to run for each port based on rarity score
    """
    # Some configured settings are overly-greedy in the default nmap config, so we
    # limit this in order to allow for a more diverse set of services.
    MAX_PORTS_PER_CONFIG = 10
    # A map of port -> config index
    services_indices_by_port = {}

    def __init__(self, configs):
        # First, sort configs by rarity. This prevents us
        # needing to do this for each list of ports later
        configs.sort(key=lambda x: x.get_directives('rarity')[0].rarity if x.has_directive('rarity') else 5)
        self.configs = configs

        for idx, config in enumerate(self.configs):
            # Get a list of ports we apply to
            ports = config.get_directive('ports').ports
            ports = ProbeFileParser.parse_ports(ports)

            # Add sslports
            if config.has_directive('sslports'):
                ssl_ports = config.get_directive('sslports').ports
                parsed_ssl_ports = ProbeFileParser.parse_ports(ssl_ports)
                for ssl_port in parsed_ssl_ports:
                    if ssl_port not in ports:
                        ports.append(ssl_port)

            # Deal with excluded ports
            if config.has_directive('exclude'):
                excluded = config.get_directive('exclude').ports
                logging.debug('Excluding ports from directive %s', excluded)

                exclude_ports = ProbeFileParser.parse_ports(excluded)
                ports = filter(lambda  x: x not in exclude_ports, ports)

            # Add the index of this config to all ports if
            # a more common service has not already grabbed it.
            consumed_ports = 0
            for port in ports:
                if consumed_ports > self.MAX_PORTS_PER_CONFIG:
                    break

                if port in self.services_indices_by_port:
                    # There is already a more viable option here.
                    continue

                self.services_indices_by_port[port] = idx
                consumed_ports += 1

    def config_iterator(self):
        for port in self.services_indices_by_port:
            idx = self.services_indices_by_port[port]
            yield port, self.configs[idx]
