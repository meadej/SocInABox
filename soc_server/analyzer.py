from rabbitmq import RabbitWorker
import json
from analyzers.virustotal import VirusTotalAnalyzer
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
            VirusTotalAnalyzer(self.config["virustotal"]),
            # TODO Add analyzers here
        ]
        self.thread_pool = Pool(len(self.analyzers))

    def new_message(self, channel, method, properties, body):
        msg = body.decode()
        if msg == "stop":
            self.stop()
            return
        print("Received message")
        packet_data = json.loads(msg)
        results = []
        for packet in packet_data["packets"]:
            results.append(self.process_packet(packet))
        print("Processed message " + str(results))
        # TODO Add to database here
        tw = 2

    @staticmethod
    def _analyze(analyzer, data):
        return analyzer.analyze(data)

    def process_packet(self, raw_packet):
        return self.thread_pool.starmap(self._analyze, [(a, Packet(raw_packet)) for a in self.analyzers])

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
