import requests as req
import psutil
from flask import Flask
from flask import render_template

app = Flask(__name__)

def get_connections():
    conns=psutil.net_connections()
    return_arr = []
    for conn in conns:
        if len(conn[4]) != 0 and conn[4][0] not in return_arr:
            return_arr.append(conn[4][0])
    return return_arr

@app.route("/")
def ui_connect():
    connected_devices = []
    for addr in get_connections():
       connected_devices.append({
           'name':'Unknown',
           'ip':addr
       })
    return render_template('dashboard.html', devices=connected_devices)   

if __name__ == "__main__":
    get_connections()
