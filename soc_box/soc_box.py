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

        # Get location & IP type
        location = ''
        ipType = ''
        if addr[0:3] == '127' or addr[0:3] == '10.' or addr[0:7] == '192.168':
            location = 'Local'
            ipType = 'N/a'
        else:
            resp = req.get('http://extreme-ip-lookup.com/json/'+str(addr)).json()
            ipType = resp['ipType']
            if resp['country'] != '':
                if resp['city'] != '':
                    location = resp['city']+', '+resp['country']
                else:
                    location = resp['country']
            # unknown location
            else:
                location = 'Unknown'
            # unknown IP type
            if ipType == '':
                ipType = 'Unknown'


        connected_devices.append({
            'name':'Unknown',
            'ip':addr,
            'location':location,
            'ipType':ipType
        })
    return render_template('dashboard.html', devices=connected_devices)   

if __name__ == "__main__":
    get_connections()
