import logging
import re
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader
import yaml


class LHConfig(object):
    PERMITTED_LOG_LEVELS = [
        'CRITICAL', 'FATAL', 'ERROR', 'WARNING', 'WARN',
        'INFO', 'DEBUG', 'NOTSET'
    ]

    def __init__(self, filename='config.yml'):
        with open(filename) as f:
            self.conf = yaml.load(f, loader=Loader)
        self._parse_logging()

    def _parse_logging(self):
        # Logging
        log_conf = self.conf.get('logging', {})
        self.file_only = log_conf.get('file_only', False)
        self.log_path = log_conf.get('out_path', 'logs')
        self.log_level = log_conf.get('level', 'DEBUG')
        self.log_rollover = log_conf.get('rollover_after_hours', 6)
        self.max_log_files = log_conf.get('max_log_files', 42)

        # Services
        service_conf = self.conf.get('services', {})
        self.service_probes_location = service_conf.get('probe_file_location', 'nmap-service-probes')

        omit_services = service_conf.get("disabled_service_types", ["honeypot"])
        self.omit_service_patterns = [re.compile(s, re.IGNORECASE) for s in omit_services]

        omit_products = service_conf.get("disabled_product_names", [".*honeypot.*",
                                                                    ".*honeyd.*",
                                                                    "Dumbster fake smtpd",
                                                                    ".*nepenthes.*"])
        self.omit_product_patterns = [re.compile(p, re.IGNORECASE) for p in omit_products]

        # Networking
        networking_conf = self.conf.get('networking')
        self.listen_port = networking_conf.get('real_port', 11337)
        self.max_ports_per_service = networking_conf.get('max_ports_per_service', 10)
        self.max_replies = networking_conf.get('max_replies', 10)

    def get_log_level(self):
        if not self.log_level.upper() in self.PERMITTED_LOG_LEVELS:
            print("Unable to parse log level. Level '{}' not recognized."
                  "Defaulting to DEBUG. Valid options: {}".format(self.log_level.upper(),
                                                                  self.PERMITTED_LOG_LEVELS))
            return logging.DEBUG
        return getattr(logging, self.log_level.upper())
