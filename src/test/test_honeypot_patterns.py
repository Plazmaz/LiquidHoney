from src.lh.config import LHConfig


class TestConfigValues(object):
    @classmethod
    def setup_class(cls):
        cls.conf = LHConfig('config.yml')

    def test_config_categories(self):
        assert self.conf.file_only == False
        assert self.conf.service_probes_location == 'nmap-service-probes'
        assert self.conf.service_probes_location == 'nmap-service-probes'
        assert self.conf.listen_port == 11337

    def test_log_lvl(self):
        # logging.DEBUG == 10
        assert self.conf.get_log_level() == 10

    def test_honeypot_patterns(self):
        with open('honeypot-strings.txt') as f:
            honeypot_services = f.readlines()

        for service in honeypot_services:
            one_matches = False
            for pattern in self.conf.omit_product_patterns:
                if pattern.match(service):
                    one_matches = True
                    break
            assert one_matches
