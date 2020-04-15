from dnslib import A
from flask import Flask, render_template, request, redirect
from threading import Thread
from sys import argv
import logging
import time
import sys

from dnslib.intercept import InterceptResolver

from datetime import datetime
from time import sleep

from dnslib import DNSLabel, QTYPE, RD, RR, CLASS
from dnslib import A, AAAA, CNAME, MX, NS, SOA, TXT
from dnslib.server import DNSServer, DNSLogger

logging.getLogger('werkzeug').setLevel(logging.ERROR)

tokens = {'tokens': [], 'used': []}

app = Flask(__name__, static_url_path='/static')


def tokenremoval(token):
    tokens['tokens'].append(token)
    time.sleep(110)
    tokens['tokens'].remove(token)


@app.route('/json', methods=['GET'])
def json():
    content = tokens
    return render_template('json.html', content=content)


@app.route('/harvest', methods=['GET', 'POST'])
def harvest():
    if request.method == "POST":
        token = request.form.get(
            'g-recaptcha-response') or request.form.get('h-captcha-response')
        if token:
            print('Posted Token : ' + token)
            Thread(target=tokenremoval, args=[token]).start()
            return redirect(request.referrer)
        else:
            return 'failed to grab response'

    c_type = request.args.get('type')
    sitekey = request.args.get('sitekey')

    if not sitekey or not c_type:
        return 'sitekey and type required'

    if c_type not in ('recaptcha', 'hcaptcha'):
        return 'invalid type'

    return render_template(c_type + '.html', sitekey=sitekey)


@app.route('/register', methods=['POST'])
def register():
    domain = request.form.get('domain')
    sitekey = request.form.get('sitekey')
    rr = RR(rname=domain + '.', rtype=QTYPE.A,
            rclass=CLASS.IN, ttl=300, rdata=A('127.0.0.1'))
    if rr.rname not in [r[0] for r in dns_resolver.zone]:
        dns_resolver.zone.append((rr.rname, QTYPE[rr.rtype], rr))

    return redirect('http//' + domain + '/harvest?type=' + 'hcaptcha' + '&sitekey=' + sitekey)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


def start(port=80, host='127.0.0.1'):
    app.run(host=host, port=port)


dns_resolver = InterceptResolver('1.1.1.1', 53, '60s', [], [], [], 5)
logger = DNSLogger('-request,-reply,-truncated,-error,-recv,-send,-data')
DNSServer(dns_resolver, port=53, address='127.0.0.1',
          logger=logger, tcp=False).start_thread()
DNSServer(dns_resolver, port=53, address='127.0.0.1',
          logger=logger, tcp=True).start_thread()

print('live on http://localhost')
start()

