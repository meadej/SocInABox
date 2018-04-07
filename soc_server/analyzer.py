from rabbitmq import RabbitWorker
import json


class SocAnalyzerServer(object):
    def __init__(self):
        self.rbw = RabbitWorker(topic="analyze_stream", binding_keys=["socbox.analyze"],
                                queue_name="socbox_analyze",
                                exclusive=False,  # Exclusive lets us persist messages in our queue through restarts
                                **{
                                    "username": "rabbitmq",
                                    "password": "rabbitmq",
                                    "host": "localhost"
                                })
        self.rbw.connect()
        self.analyzers = []

    def new_message(self, channel, method, properties, body):
        msg = body.decode()
        if msg == "stop":
            self.stop()
            return
        print("Received message")
        packet_data = json.loads(msg)
        for packet in packet_data["packets"]:
            self.process_packet(packet)

    def process_packet(self, packet):
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
