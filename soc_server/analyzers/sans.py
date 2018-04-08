from analyzers import BaseAnalyzer, Status


class SansAnalyzer(BaseAnalyzer):
    def __init__(self, config):
        super(SansAnalyzer, self).__init__()
        self.amber_threat_list = self.generate_threat_list("analyzers/sans_db/amber.txt")
        self.red_threat_list = self.generate_threat_list("analyzers/sans_db/red.txt")

    def ip_to_domain(self, ip_address):
        response = self.request("GET", "http://extreme-ip-lookup.com/json/" + str(ip_address))
        response_json = response.json()
        return response_json['businessWebsite']

    @staticmethod
    def generate_threat_list(location):
        try:
            handle = open(location, 'r')
            return_array = []
            for line in handle.readlines():
                if not line.startswith("#"):
                    return_array.append(line.strip())
            return return_array
        except Exception as e:
            print(str(e))
            return []

    def analyze(self, packet):
        domain = self.ip_to_domain(packet.dst_ip)
        if domain in self.red_threat_list:
            return Status.Red()
        elif domain in self.amber_threat_list:
            return Status.Amber()
        else:
            return Status.White()

