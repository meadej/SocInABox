from flask import Flask
from flask import request
import requests as req

def build_iptable_rule():
    #TODO: Actually use python to add to firewall
    return

@app.route('/check', methods=['POST'])
def receive_response():
    """
    Takes in a POST response from the soc server with a set of ips and a yes/no status.
    """
    if request.method == 'POST':
        packet_data = {}
        packet_data['src_ip'] = request.form['src_ip']
        packet_data['dest_ip'] = request.form['dest_ip']
        packet_data['status'] = request.form['status']
        
    return
