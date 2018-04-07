from rabbitmq import RabbitWorker
import json
from analyzers import VirusTotalAnalyzer
from multiprocessing import Pool


class Packet(object):
    def __init__(self, packet):
        self.src_mac = packet["source_MAC"]
        self.dst_mac = packet["dest_MAC"]
        self.src_ip = packet["source_IP"]
        self.dst_ip = packet["dest_IP"]
        self.src_port = packet["source_port"]
        self.dst_port = packet["dest_port"]


class SocAnalyzerServer(object):
    def __init__(self):
        self.config = json.load(open("config.json", "r"))
        self.rbw = RabbitWorker(topic="analyze_stream", binding_keys=["socbox.analyze"],
                                queue_name="socbox_analyze",
                                exclusive=False,  # Exclusive lets us persist messages in our queue through restarts
                                **self.config["rabbit"])
        self.rbw.connect()
        self.analyzers = [
            VirusTotalAnalyzer(self.config["virustotal"])
        ]
        self.thread_pool = Pool(len(self.analyzers))

    def new_message(self, channel, method, properties, body):
        msg = body.decode()
        if msg == "stop":
            self.stop()
            return
        print("Received message")
        packet_data = json.loads(msg)
        for packet in packet_data["packets"]:
            self.process_packet(packet)

    @staticmethod
    def _analyze(analyzer, data):
        return analyzer.analyze(data)

    def process_packet(self, raw_packet):
        packet = Packet(raw_packet)
        results = self.thread_pool.starmap(self._analyze, [(a, packet) for a in self.analyzers])
        tw = 2
        # Sample incoming packet
        # {
        #     "source_MAC": "10:8c:cf:57:2e:00",
        #     "dest_MAC": "78:4f:43:6a:60:62",
        #     "source_IP": "35.160.31.12",
        #     "dest_IP": "10.202.8.115",
        #     "source_port": 443,
        #     "dest_port": 51168
        # }

    def start(self):
        self.rbw.start_consume(self.new_message)

    def stop(self):
        print("Stopping..")
        self.rbw.stop_consume()
        self.rbw.disconnect()


if __name__ == "__main__":
    sa = SocAnalyzerServer()
    print("Starting")
    sa.start()
    print("Exiting")
