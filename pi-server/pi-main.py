from flask import Flask
from flask import request
import requests as req
import os

def execute_iptable_rule(rule):
    os.system(rule)

def build_iptable_rule(packet_data):
    rule_dict = {}
    rule_dict['-A'] = 'OUTPUT'
    rule_dict['-p'] = 'udp'
    rule_dict['-d'] = packet_data['dest_ip']
    rule_string = "iptables "
    for key in rule_dict.keys:
        rule_string += " " + str(key) + " " + str(rule_dict[key])
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
        if packet_data['status'] == 'bad':
            #TODO: Agree on what status flags should be
            new_rule = build_iptable_rule(packet_data)
            execute_iptable_rule(new_rule)
    return
