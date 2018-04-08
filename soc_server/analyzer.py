import json
import pendulum
from rabbitmq import RabbitWorker
from multiprocessing import Pool
from pymongo import MongoClient
from analyzers.virustotal import VirusTotalAnalyzer
from analyzers.sans import SansAnalyzer
from analyzers import Status


class Packet(object):
    def __init__(self, packet):
        self.src_mac = packet["source_MAC"]
        self.dst_mac = packet["dest_MAC"]
        self.src_ip = packet["source_IP"]
        self.dst_ip = packet["dest_IP"]
        self.src_port = packet["source_port"]
        self.dst_port = packet["dest_port"]

    def to_cache_entry(self, analyzed_res, timestamp):
        vals = [color.val for color in analyzed_res]
        status = Status.get_status(analyzed_res)
        return {
            "ip": self.dst_ip,
            "val": vals,
            "status": status,
            "timestamp": timestamp.to_iso8601_string()
        }


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
            SansAnalyzer(self.config["sans"]),
            # TODO Add analyzers here
        ]
        self.thread_pool = Pool(len(self.analyzers))

        self.client = MongoClient(self.config["mongo"])
        self.cache_col = self.client.socinabox.soc_cache

    # Checks if the packet is cached, removing it if it's outdated
    def is_cached_packet(self, packet, timestamp):
        is_in_db = self.cache_col.find_one({"ip": packet.dst_ip})  # Sorted by destination IP
        if is_in_db:
            dt = pendulum.parse(is_in_db["timestamp"])
            if (timestamp - dt).in_seconds() > self.config["timestamp_expire_sec"]:
                self.cache_col.delete_many({"ip": packet.dst_ip})
                return None  # We found a timestamp, but it's outdated, so replace it
            else:
                is_in_db.pop("_id")
                return is_in_db
        else:
            return None

    # Adds new packet entries to the mongo db
    def update_cache(self, entries):
        self.cache_col.insert_many(entries)

    # Used to convert this color status into an entry, given the associated packet
    def new_message(self, channel, method, properties, body):
        timestamp = pendulum.now()

        msg = body.decode()
        if msg == "stop":
            self.stop()
            return
        print("Received message")
        packet_data = json.loads(msg)
        results = []
        for raw_packet in packet_data["packets"]:  # TODO Map this with multithreading
            packet = Packet(raw_packet)
            cached = self.is_cached_packet(packet, timestamp)

            if not cached:
                analyzed_results = self.process_packet(packet)
                results.append(packet.to_cache_entry(analyzed_results, timestamp))
        if results:
            print("Updating database")
            self.update_cache(results)
        else:
            print("No new entries")
        print("Processed message " + str(results))

    @staticmethod
    def _analyze(analyzer, data):
        return analyzer.analyze(data)

    def process_packet(self, packet):
        return self.thread_pool.starmap(self._analyze, [(a, packet) for a in self.analyzers])

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


    # Mongo Schema
    # {"ip": "<ip>", "status": "<TLP color>", "timestamp": "<iso 8601 timestamp>", "val": "<val [0-1]>}
