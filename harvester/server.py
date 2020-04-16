import ipaddress
import proxy
from flask import Flask, Response, jsonify
import os
import threading
from expiring_queue import ExpiringQueue

if os.name != 'nt':  # avoid freeze_support error on Windows
    import store

tokens = ExpiringQueue(110)

app = Flask(__name__, static_url_path='/static')


@app.route('/tokens', methods=['GET'])
def tokens_route():
    return jsonify(list(tokens.queue))


@app.route('/token', methods=['GET'])
def token():
    if tokens.empty():
        return Response(status=418)
    return tokens.get()


def start(port=5000, host='127.0.0.1'):
    app.run(host=host, port=port)


def queue_worker():
    while True:
        tokens.put(store.tokens.get())


if __name__ == '__main__':
    if os.name == 'nt':  # avoid freeze_support error on Windows
        import store

    store.host_map['sneakersnstuff.com'] = {
        'type': 'hcaptcha',
        'sitekey': '33f96e6a-38cd-421b-bb68-7806e1764460'
    }

    threading.Thread(target=queue_worker, daemon=True).start()
    with proxy.start(hostname=ipaddress.IPv4Address('127.0.0.1'), plugins='plugin.MyManInTheMiddlePlugin'):
        start()
