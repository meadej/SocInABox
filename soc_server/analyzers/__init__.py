import requests


class Status(object):
    RED = "RED"  # Result is negative
    GREEN = "GREEN"  # Result is positive
    AMBER = "AMBER"  # Result is unknown/needs user interaction
    WHITE = "WHITE"  # Result couldn't be obtained


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

