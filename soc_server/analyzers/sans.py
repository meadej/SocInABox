from analyzers import BaseAnalyzer,Status

class SansAnalyzer(BaseAnalyzer):
	def __init__(self, config):
		super(SansAnalyzer, self).__init__()
		self.amber_threat_list = self.generate_threat_list("sans_db/amber.txt")
		self.red_threat_list = self.generate_threat_list("sans_db/red.txt")

	def ip_to_domain(self, ip_address):
		response = self.request("GET", "extreme-ip-lookup.com/json/" + str(ip_address))
		response_json = response.json()
		return response_json['businessWebsite']

	def generate_threat_list(self, location):
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
		try:
			domain = ip_to_domain(packet.dst_ip)
			if domain in red_threat_list:
				return Status.Red()
			elif domain in amber_threat_list:
				return Status.Amber()
			else:
				return Status.White()
		except Exception as e:
			print(str(e))
			return Status.White()


