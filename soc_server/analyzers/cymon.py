from analyzers import BaseAnalyzer, Status
from cymon import Cymon


class CymonAnalyzer(BaseAnalyzer):
    def __init__(self, config):
        super(CymonAnalyzer, self).__init__()
        self.cymon = Cymon(config["api_key"])

    def analyze(self, packet):
        data = self.cymon.ip_events(packet.dst_ip)
        if packet.dst_ip == "8.8.8.8":
            return Status.Green()

        if "results" in data:
            if data["results"]:
                return Status.Red(len(data["results"]))
            else:
                return Status.White()

