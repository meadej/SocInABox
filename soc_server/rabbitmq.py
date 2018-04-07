import pika
from pika.credentials import PlainCredentials


class RabbitMQ(object):
    def __init__(self, username, password, host):
        pc = PlainCredentials(username=username, password=password)
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=host, credentials=pc))
        self.channel = self.connection.channel()


class RabbitWorker(RabbitMQ):
    def __init__(self, username, password, host, topic, queue_name, binding_keys, exclusive=True):
        super(RabbitWorker, self).__init__(username, password, host)
        self.queue_name = queue_name
        self.topic = topic
        self.binding_keys = binding_keys
        self.consuming = False
        self.connected = False
        self.exclusive = exclusive

    def connect(self):
        self.channel.exchange_declare(exchange=self.topic, exchange_type='topic')
        # Exclusive makes the queue be deleted once the consumer is removed
        self.channel.queue_declare(exclusive=self.exclusive, queue=self.queue_name)
        for binding_key in self.binding_keys:
            self.channel.queue_bind(exchange=self.topic,
                                    queue=self.queue_name,
                                    routing_key=binding_key)
        self.connected = True

    def start_consume(self, callback):
        if not self.consuming and self.connected:
            # Signature of callback
            # def callback(ch, method, properties, body):
            self.channel.basic_consume(callback,
                                       queue=self.queue_name,
                                       no_ack=True)
            # Don't tell the broker that we've gotten the message with no_ack
            self.channel.start_consuming()
            self.consuming = True
        else:
            raise Exception("Not connected, call connect()")

    def stop_consume(self):
        if self.consuming:
            self.channel.stop_consuming()

    def disconnect(self):
        if self.connected:
            self.stop_consume()
            self.connection.close()
            self.connected = False


class RabbitProducer(RabbitMQ):
    def __init__(self, username, password, host, topic, routing_key, exchange_type='topic'):
        super(RabbitProducer, self).__init__(username, password, host)
        self.topic = topic
        self.routing_key = routing_key
        self.connected = False
        self.exchange_type = exchange_type

    def connect(self):
        self.channel.exchange_declare(exchange=self.topic, exchange_type=self.exchange_type)
        self.connected = True

    def publish(self, message):
        self.channel.basic_publish(exchange=self.topic,
                                   routing_key=self.routing_key,
                                   body=message)

    def disconnect(self):
        if self.connected:
            self.connection.close()
            self.connected = False
