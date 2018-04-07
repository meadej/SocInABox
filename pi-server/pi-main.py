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
    rule_dict['-j'] = 'DROP'
    rule_dict['-d'] = packet_data['dest_ip']
    rule_string = "iptables "
    for key in rule_dict.keys:
        rule_string += " " + str(key) + " " + str(rule_dict[key])
    return

@app.route('/response', methods=['POST'])
def receive_response():
    """
    Takes in a POST response from the soc server with a set of ips and a yes/no status.
    """
    if request.method == 'POST':
        ip_data = request.form[rules]
        rule_data['dest_ip'] = ip_data['ip']
        rule_data['status'] = ip_data['status']        
        if ip_data['status'] == 'RED':
            new_rule = build_iptable_rule(rule_data)
            execute_iptable_rule(new_rule)
	elif ip_data['status'] == 'AMBER':
            #TODO: Notify user
            return
    return
