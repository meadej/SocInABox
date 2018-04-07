import requests as req
import os
import json

"""
Functions to ping the soc server, retreive new firewall rules, and add them to the
local system
"""

def execute_iptable_rule(rule):
    os.system(rule)

def build_iptable_rule(packet_data):
    rule_dict = {
        '-A':'OUTPUT',
        '-p':'udp',
        '-j':'DROP',
        '-d':packet_data['dest_ip']
    }
    rule_string = "iptables "
    for key in rule_dict.keys:
        rule_string += " " + str(key) + " " + str(rule_dict[key])
    return      

def get_firewall_updates(soc_server_location):
    return req.get(soc_server_location)

def update_firewall():
    server_location = "" #IP Address here
    new_rules = get_firewall_updates(server_location)
    rules_dict = json.loads(new_rules)['rules']
    for rule in rules_dict.keys():
        if [rules_dict][rule]['status'] == "RED":
            new_rule = build_iptable_rule(rules_dict[rule])
        elif [rules_dict][rule]['status'] == "RED":
            #TODO: Notify user
            return
    return

if __name__ == "__main__":
    update_firewall()
