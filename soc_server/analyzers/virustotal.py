from analyzers import BaseAnalyzer, Status
import time


class VirusTotalAnalyzer(BaseAnalyzer):
    def __init__(self, config):
        super(VirusTotalAnalyzer, self).__init__()
        self.api_key = config["api_key"]

    def ip_report(self, ip):
        return self.request("GET", "https://www.virustotal.com/vtapi/v2/ip-address/report",
                            params={"ip": ip, "apikey": self.api_key})

    def analyze(self, packet):
        try:
            done = False
            response = self.ip_report(packet.dst_ip)
            while not done:
                if response.status_code != 204:  # We're out of calls currently, wait a bit
                    done = True
                else:
                    print("VirusTotal API Key limit, sleeping..")
                    time.sleep(30)  # TODO Sleep b/c api token is exhausted, More tokens?
                    response = self.ip_report(packet.dst_ip)
            data = response.json()
            if data["response_code"] == 0:
                return Status.White()  # Not in VirusTotal Database
            elif data["response_code"] == 1:
                if not data["detected_urls"]:
                    return Status.Green()
                else:
                    avg = 8  # TODO calc avg
                    return Status.Red(avg)
            else:
                raise Exception("Invalid response code: {}".format(data["response_code"]))
        except Exception as e:
            print("Error in VirusTotal! " + str(e))
            return Status.White()
