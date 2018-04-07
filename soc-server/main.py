from flask import Flask
from flask import request
import requests as req

app = Flask(__name__)
@app.route('/check', methods=['POST'])
def check():
    """
    Takes in a POST request with the src_ip and dest_ip set and processes them through the static analysis/ML checker.
    """
    if request.method == 'POST':
        packet_data = {}
        packet_data['src_ip'] = request.form['src_ip']
        packet_data['dest_ip'] = request.form['dest_ip']
        #TODO: Pass packet_data dict to processing program
        # Have processing program call back to respond() below
    return

def respond(pi_ip, packet_data, packet_status):
    """
    Sends a packet ok/ packet not ok message back to the pi and firewall.
    """
    packet_data['status'] = packet_status
    requests.post(pi_ip, data=packet_data)
    return
