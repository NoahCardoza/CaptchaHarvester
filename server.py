from flask import Flask, render_template, request
from threading import Thread
from sys import argv
import logging, time, sys

logging.getLogger('werkzeug').setLevel(logging.ERROR)

tokens = {'tokens':[],'used':[]}

app = Flask(__name__)

def tokenremoval(token):
    tokens['tokens'].append(token)
    time.sleep(110)
    tokens['tokens'].remove(token)

@app.route('/json', methods=['GET'])
def json():
    content = tokens
    return(render_template('json.html', content = content))

@app.route('/solve', methods=['POST'])
def solve():
    if request.method == "POST":
        token = request.form.get('g-recaptcha-response', '')
        print('Posted Token : ' + token)
        Thread(target = tokenremoval, args = [token]).start()
    return('Success')

@app.route('/used', methods=['POST'])
def used():
    token = request.form.get('usedtoken', '')
    print('Used Token : ' + token)
    tokens['used'].append(token)
    return('Success')

Thread(target = lambda: app.run(host = '0.0.0.0')).start()
