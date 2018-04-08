import requests as req
import psutil
import requests
import pendulum
from jinja2 import Environment, PackageLoader, select_autoescape
import json
from flask import Flask, redirect
# from flask import render_template

app = Flask(__name__)

timestamp = "2018-04-08T09:32:44-06:00" # pendulum.now().to_iso8601_string()
HOST_URL = "http://127.0.0.1:5001"
SERVER_URL = "http://127.0.0.1:5000"


def render_template(template, **kwargs):
    env = Environment(
        loader=PackageLoader('soc_box', 'templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )
    return env.get_template(template).render(**kwargs)


def get_connections():
    conns = psutil.net_connections()
    return_arr = []
    for conn in conns:
        if len(conn[4]) != 0 and conn[4][0] not in return_arr:
            return_arr.append(conn[4][0])
    return return_arr


@app.route("/update")
def ui_update():
    try:
        resp = requests.request("GET", "{}/update".format(SERVER_URL), params={"timestamp": timestamp})
        # tmp_timestamp = pendulum.now().to_iso8601_string()
        data = resp.json()
        rules = {}
        with open("rules.json", "r") as f:
            rules = json.loads("".join(f.readlines()))
            for rule in data["rules"]:
                rules[rule["ip"]] = {
                    "status": rule["status"],
                    "timestamp": rule["timestamp"]
                }
        if rules:
            with open("rules.json", "w") as f:
                f.write(json.dumps(rules))
        return redirect("{}/rules".format(HOST_URL), code=200)
    except Exception as e:
            return "Error getting update! " + str(e)


@app.route("/rules")
def ui_rules():
    try:
        with open("rules.json", "r") as f:
            return render_template('rules.html', rules=json.loads("".join(f.readlines())), home=HOST_URL)
    except Exception as e:
        return "Error getting rules! " + str(e)



@app.route("/")
def ui_connect():
    connected_devices = []
    for addr in get_connections():
        # Get location & IP type
        location = ''
        ipType = ''
        if addr[0:3] == '127' or addr[0:3] == '10.' or addr[0:7] == '192.168':
            location = 'Local'
            ipType = 'N/a'
        else:
            resp = req.get('http://extreme-ip-lookup.com/json/' + str(addr)).json()
            if resp["status"] != "fail":
                ipType = resp['ipType']
                if resp['country'] != '':
                    if resp['city'] != '':
                        location = resp['city'] + ', ' + resp['country']
                    else:
                        location = resp['country']
                # unknown location
                else:
                    location = 'Unknown'
                # unknown IP type
                if ipType == '':
                    ipType = 'Unknown'

            connected_devices.append({
                'name': 'Unknown',
                'ip': addr,
                'location': location,
                'ipType': ipType
            })
    return render_template('dashboard.html', devices=connected_devices, home=HOST_URL)
