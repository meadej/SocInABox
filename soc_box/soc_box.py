import requests as req
import os
import json
from flask import Flask
from flask import render_template

app = Flask(__name__)

@app.route("/")
def ui_connect():
    return render_template('dashboard.html', devices=[{'name':'Phillips Lightbulb', 'ip':'192.168.1.1'}])   
