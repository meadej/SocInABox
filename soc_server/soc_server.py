from flask import Flask
from flask import request as req
import jsonschema
import pendulum
import json
# from soc_server.analyzer import SocAnalyzer
from soc_server.rabbitmq import RabbitProducer

app = Flask(__name__)
config = json.load(open("config.json", "r"))


# Make a response to being given new information
def make_status_response(status, message):
    return json.dumps({
        "status": status,
        "message": message
    })


# Make a response to update with new rules
def make_update_response(rules):
    return json.dumps({
        "timestamp": pendulum.now().to_iso8601_string(),
        "rules": rules
    })


# Takes in a POST request with the src_ip and dst_ip set and processes them through the static analysis/ML checker.
@app.route('/check', methods=['POST'])
def check():
    if req.method == "POST":
        packet_data = req.get_json()
        if not packet_data:
            return make_status_response("RED", "No data sent")

        # Validate input to schema
        with open("schemas/new_packet.schema.json", "r") as f:
            schema = jsonschema.Draft4Validator(json.load(f))
            message = "\n".join([str(s) for s in list(schema.iter_errors(packet_data))])
            if message:
                return make_status_response("RED", message)
        rbp = RabbitProducer(topic="analyze_stream", routing_key="socbox.analyze", **config["rabbit"])

        rbp.connect()
        # TODO Add stop?
        # rbp.publish("stop")
        rbp.publish(json.dumps(packet_data))
        rbp.disconnect()
        return make_status_response("GREEN", "got {} packets".format(len(packet_data["packets"])))
    else:
        return make_status_response("RED", "Invalid method type, use POST!")


# Given an update query, get the new rules to be applied
@app.route('/update', methods=['GET'])
def update():
    return make_update_response([  # TODO Get actual data from db here
        {"ip": "123.123.123.123", "status": "RED"},
        {"ip": "124.124.124.124.", "status": "GREEN"}
    ])



    # Expected input
    # {
    #     "packets": [
    #         {"source_MAC": "10:8c:cf:57:2e:00", "dest_MAC": "78:4f:43:6a:60:62", "source_IP": "35.160.31.12",
    #          "dest_IP": "10.202.8.115", "source_port": 443, "dest_port": 51168},
    #         {"source_MAC": "78:4f:43:6a:60:62", "dest_MAC": "10:8c:cf:57:2e:00", "source_IP": "10.202.8.115",
    #          "dest_IP": "35.160.31.12", "source_port": 51170, "dest_port": 443}
    #     ]
    # }


    # Ouput
    # {
    #     "timestamp": "<iso thing>",
    #     "rules": [
    #         {"ip": "123.123.123.123", "status": "GREEN"}, //Good
    #         {"ip": "234.234.234.234", "status": "RED"}, //Bad
    #         {"ip": "163.163.163.163", "status": "AMBER"}, //Maybe? (user interaction?)
    #     ]
    # }


