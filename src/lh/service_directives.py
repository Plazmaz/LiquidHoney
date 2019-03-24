from abc import ABC


class ProbeConfig(object):
    def __init__(self):
        self.directives = {}

    def add_directive(self, directive):
        name = directive.keyword
        if name not in self.directives:
            self.directives[name] = []
        self.directives[name].append(directive)

    def get_directives(self, name):
        return self.directives.get(name)

    def has_directive(self, name):
        return name in self.directives

    def get_directive(self, name):
        return self.directives.get(name)[0]

    def __str__(self):
        return ' '.join([s for s in self.directives])


class Directive(ABC):
    """
    Represents a directive type.
    See https://nmap.org/book/vscan-fileformat.html
    """

    def __init__(self, keyword, param_count, raw):
        self.keyword = keyword
        self.raw = raw
        self.parameters = raw.split(" ", param_count)[1:]

    def validate(self):
        pass


class Exclude(Directive):
    """
    This line tells nmap what ports identified by the probe are found on
    (only once per section)
    """

    def __init__(self, raw):
        super().__init__('exclude', 1, raw)
        # This will need to be parsed into proper port format later
        self.ports = self.parameters[0]


class Probe(Directive):
    """
    This directive describes what nmap will send to fingerprint this service
    """

    def __init__(self, raw):
        super().__init__('probe', 3, raw)
        self.protocol = self.parameters[0]
        self.probename = self.parameters[1]
        self.probestring = self.parameters[2]

    def validate(self):
        assert self.protocol == 'TCP' or self.protocol == 'UDP', \
            'Invalid protocol {} found, expected "UDP" or "TCP"'.format(self.protocol)


class Match(Directive):
    """
    This directive describes the response nmap is expecting to recieve for a service
    """

    def __init__(self, raw):
        super().__init__('match', 2, raw)
        self.service = self.parameters[0]
        self.raw_pattern = self.parameters[1]
        self.pattern = None
        self.flags = []
        self.version_info = []


class SoftMatch(Match):
    """
    Similar to match, but after a softmap, nmap will only send probes matching the given service.
    This is intended to eventually lead to a 'hard' match that will provide more version info
    """

    def __init__(self, raw):
        super().__init__(raw)
        self.service = self.parameters[0]
        self.raw_pattern = self.parameters[1]
        self.keyword = 'softmatch'


class Ports(Directive):
    """
    This line tells nmap what ports identified by the probe are found on
    (only once per section)
    """

    def __init__(self, raw):
        super().__init__('ports', 1, raw)
        # This will need to be parsed into proper port format later
        self.ports = self.parameters[0]


class SslPorts(Ports):
    """
    Same as Ports, but wrapped in ssl
    """

    def __init__(self, raw):
        super().__init__(raw)
        self.keyword = 'sslports'


class Rarity(Directive):
    """
    Determines how frequently a probe returns useful results. The higher the number, the rarer the probe is
    https://nmap.org/book/vscan-technique.html#vscan-selection-and-rarity
    """

    def __init__(self, raw):
        super().__init__('rarity', 1, raw)
        self.rarity = self.parameters[0]
