class Packet(object):
    def __init__(self, packet):
        self.src_mac = packet["source_MAC"]
        self.dst_mac = packet["dest_MAC"]
        self.src_ip = packet["source_IP"]
        self.dst_ip = packet["dest_IP"]
        self.src_port = packet["source_port"]
        self.dst_port = packet["dest_port"]


class BaseAnalyzer(object):
    # Returns a status, "RED" -> bad, "GREEN" -> ok, "AMBER" -> unknown/user interaction needed
    def analyze(self, packet):
        raise NotImplementedError("Can't use BaseAnalyzer!")


class VirusTotalAnalyzer(BaseAnalyzer):
    def __init__(self, config):

    def analyze(self, packet):
        pass