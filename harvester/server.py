import json
import cgi
from urllib import parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from expiring_queue import ExpiringQueue

tokens = ExpiringQueue(110)


def my_render_template(file, **args):
    with open('templates/' + file, 'r') as f:
        template = f.read()
        for k, v in args.items():
            template = template.replace('{{ ' + k + ' }}', v)
    return template


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def _find_config(self):
        location = parse.urlparse(self.path)
        self.config = host_map.get(location.netloc)
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
        # host = self.path.split(':', 1)[0]
        print('WARNING: make sure to use http not https when accessing the host.')
        self.connection.close()

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
            message = my_render_template(
                self.config['type'] + '.html', sitekey=self.config['sitekey'])
            self.wfile.write(message.encode('utf-8'))


if __name__ == '__main__':
    # TODO: clean this whole file up

    host = '127.0.0.1'
    proxy_port = 8899
    flask_port = 8000

    host_map = {}
    host_map['www.sneakersnstuff.com'] = {
        'type': 'hcaptcha',
        'sitekey': '33f96e6a-38cd-421b-bb68-7806e1764460'
    }

    proxy_server = HTTPServer((host, proxy_port), ProxyHTTPRequestHandler)
    proxy_server.serve_forever()
