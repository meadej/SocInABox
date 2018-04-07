import requests


class Packet(object):
    def __init__(self, packet):
        self.src_mac = packet["source_MAC"]
        self.dst_mac = packet["dest_MAC"]
        self.src_ip = packet["source_IP"]
        self.dst_ip = packet["dest_IP"]
        self.src_port = packet["source_port"]
        self.dst_port = packet["dest_port"]


class Status(object):
    RED = 0
    GREEN = 1
    AMBER = 2


class BaseAnalyzer(object):
    def __init__(self):
        self.session = requests.Session()

    def request(self, method, url, **kwargs):
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    # Returns a Status
    def analyze(self, packet):
        raise NotImplementedError("Can't use BaseAnalyzer!")


class VirusTotalAnalyzer(BaseAnalyzer):
    def __init__(self, config):
        super(VirusTotalAnalyzer, self).__init__()
        self.session.params = {'apikey': config["api_key"]}

    def analyze(self, packet):
        response = self.request("GET", "https://www.virustotal.com/vtapi/v2/ip-address/report",
                                params={"ip": packet.dst_ip})

        return Status.GREEN  # TODO ChangeMe

