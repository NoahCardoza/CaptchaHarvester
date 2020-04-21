import json
import cgi
from urllib import parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from expiring_queue import ExpiringQueue
from os import path

__dir__ = path.dirname(path.abspath(__file__))
tokens = ExpiringQueue(110)
mitm_cache = {}


def my_render_template(file, **args):
    with open(path.join(__dir__, 'templates', file), 'r') as f:
        template = f.read()
        for k, v in args.items():
            template = template.replace('{{ ' + k + ' }}', v)
    return template


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def _find_config(self):
        location = parse.urlparse(self.path)
        self.config = mitm_cache.get(location.netloc)
        if not self.config:
            self.send_response(404)

            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()

            message = 'CaptchaHarvester {} not being intercepted.'.format(
                location.netloc)

            self.wfile.write(message.encode('utf-8'))
            return None
        return self.config

    def do_CONNECT(self):
        print('WARNING: make sure to use http not https when accessing the host.')

    def do_GET(self):
        self.handel_request('GET')

    def do_POST(self):
        self.handel_request('POST')

    def handel_request(self, method):
        if self.path.startswith('/'):
            if self.path.startswith('/tokens'):
                self.send_response(200)
                self.send_header('Content-Type', 'text/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps(
                    list(tokens.queue)).encode('utf-8'))
            elif self.path.startswith('/token'):
                if tokens.empty():
                    self.send_response(418)
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header(
                        'Content-Type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(tokens.get().encode('utf-8'))
        elif self._find_config():
            if method == 'POST':
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        'REQUEST_METHOD': 'POST',
                        'CONTENT_TYPE': self.headers['Content-Type'],
                    }
                )
                token = form.getvalue(
                    'h-captcha-response') or form.getvalue('g-recaptcha-response')
                if token:
                    tokens.put(token)

            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            host, port = self.server.server_address
            message = my_render_template(
                self.config['type'] + '.html', sitekey=self.config['sitekey'], server=f"http://{host}:{port}")
            self.wfile.write(message.encode('utf-8'))


def start(host, port, domain, captcha_type, sitekey):
    mitm_cache[domain] = {
        'type': captcha_type,
        'sitekey': sitekey
    }

    httpd = ThreadingHTTPServer((host, port), ProxyHTTPRequestHandler)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
