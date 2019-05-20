import logging
import re

from src.lh.service_directives import Exclude, Probe, Match, SoftMatch, Ports, SslPorts, Rarity, ProbeConfig


class ProbeFileParser(object):
    cur_probe = None
    FLAG_FORMAT = re.compile(r'(?:[pvihod]|cpe:)/([^/]+)/[a-z]?')
    MATCH_FORMAT = re.compile(r'^m(.)(.*?)(?:\1)([a-z]+)?')

    PROBE_BORDER = '##############################NEXT PROBE##############################'
    DIRECTIVE_MAP = {
        'exclude': Exclude,
        'probe': Probe,
        'match': Match,
        'softmatch': SoftMatch,
        'ports': Ports,
        'sslports': SslPorts,
        'rarity': Rarity,
    }

    def __init__(self, conf):
        self.conf = conf
        self.filename = conf.service_probes_location

    @staticmethod
    def parse_ports(ports):
        return_ports = []
        for port in ports.split(','):
            port = port.strip()
            if '-' in port:
                parts = port.split('-')
                min_port = int(parts[0])
                max_port = int(parts[1])
                for i in range(min_port, max_port + 1):
                    return_ports.append(i)
            else:
                return_ports.append(int(port))
        return return_ports

    def _complete_match(self, match):
        pattern = match.raw_pattern
        if not pattern[0] == 'm':
            logging.error("Unexpected error parsing pattern! Math must begin with 'm'.")

        # Parse version flags
        version_info = [m.group(1) for m in self.FLAG_FORMAT.finditer(pattern)]
        match.version_info = version_info

        pattern_info = self.MATCH_FORMAT.search(pattern)
        match.pattern = pattern_info.group(2)

    def iter_parse(self):
        self.start_probe()
        with open(self.filename, encoding="utf8") as f:
            for line in f.readlines():
                line = line.strip()
                if line == self.PROBE_BORDER:
                    if 'ports' in self.cur_probe.directives:
                        yield self.cur_probe
                    self.start_probe()
                directive = line.split(' ')[0].lower().strip()
                if not directive:
                    continue
                if directive.startswith('#'):
                    continue
                if directive.startswith('\n'):
                    continue

                if directive not in self.DIRECTIVE_MAP:
                    logging.warning('Unable to parse directive "%s". Skipping.', line[:-1])
                    continue

                parsed_directive = self.DIRECTIVE_MAP[directive](line)
                if isinstance(parsed_directive, Match):
                    self._complete_match(parsed_directive)

                    blacklist_skip = False
                    # Check service blacklist
                    for pattern in self.conf.omit_service_patterns:
                        if pattern.match(parsed_directive.service):
                            logging.warning('Skipping line due to matching service blacklist item "%s". Line: "%s"',
                                            pattern.pattern, line[:-1])
                            blacklist_skip = True

                            # Break inner loop
                            break

                        # Break outer loop
                        if blacklist_skip:
                            break

                    # Check product blacklist
                    for pattern in self.conf.omit_product_patterns:
                        for product in parsed_directive.parameters:
                            if pattern.match(product):
                                logging.warning('Skipping line due to matching product blacklist item "%s". Line: "%s"',
                                                pattern.pattern, line[:-1])
                                blacklist_skip = True

                                # Break inner loop
                                break

                            # Break outer loop
                            if blacklist_skip:
                                break
                    # Skip this directive.
                    if blacklist_skip:
                        continue
                self.cur_probe.add_directive(parsed_directive)
        yield self.cur_probe

    def start_probe(self):
        if self.cur_probe:
            logging.debug('Found directive %s', self.cur_probe)

        self.cur_probe = ProbeConfig()
