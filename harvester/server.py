import ipaddress
import proxy
from flask import Flask, jsonify
import logging
import store

logging.getLogger('werkzeug').setLevel(logging.ERROR)

app = Flask(__name__, static_url_path='/static')


@app.route('/json', methods=['GET'])
def json():
    return jsonify(store.tokens._getvalue())  # pylint: disable=E1101


def start(port=5000, host='127.0.0.1'):
    app.run(host=host, port=port)


if __name__ == '__main__':
    store.host_map[b'sneakersnstuff.com'] = {
        'type': 'hcaptcha',
        'sitekey': '33f96e6a-38cd-421b-bb68-7806e1764460'
    }

    with proxy.start(hostname=ipaddress.IPv4Address('127.0.0.1'), plugins='plugin.MyManInTheMiddlePlugin'):
        start()
