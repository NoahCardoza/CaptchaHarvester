import json
import cgi
from os import path
from enum import Enum
from urllib import parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .expiring_queue import ExpiringQueue
from queue import Queue
from dataclasses import dataclass
from typing import Dict, Union, Tuple
import logging
import sys
import ssl

log = logging.getLogger('harvester')
sh = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    '%(name)s(%(levelname)s) [%(timestamp)s] [%(address)s] %(message)s')
sh.setFormatter(formatter)
log.addHandler(sh)


class CaptchaKindEnum(Enum):
    HCAPTCHA = 'hcaptcha'
    RECAPTCHA_V2 = 'recaptcha-v2'
    RECAPTCHA_V3 = 'recaptcha-v3'


@dataclass
class MITMRecord:
    kind: CaptchaKindEnum
    sitekey: str
    data_action: str


# support for pyarmor/pyinstaller
__dir__ = path.join(getattr(sys, '_MEIPASS'), 'harvester', 'server') if getattr(
    sys, '_MEIPASS', None) else path.abspath(path.dirname(__file__))
MITM_CAHCE: Dict[str, MITMRecord] = {}
tokens: 'ExpiringQueue[str]' = ExpiringQueue(110)


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def _render_template(self, file: str, **args: Dict[str, Union[str, int]]):
        with open(path.join(__dir__, 'templates', file), 'r') as f:
            template = f.read()
        for k, v in args.items():
            template = template.replace('{{ ' + k + ' }}', str(v))

        self.wfile.write(template.encode('utf-8'))

    def _find_config(self):
        location = parse.urlparse(self.path)
        self.config = MITM_CAHCE.get(location.netloc)
        if not self.config:
            self.send_error(404,
                            'Not intercepted',
                            'CaptchaHarvester not intercepting ' + location.netloc)
            return None
        return self.config

    def _simple_headers(self, code: int, content_type: str):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.end_headers()

    def do_CONNECT(self):
        self.send_error(
            500, "Yuck! hTtPs", 'Make sure to use http:// not https:// when accessing the host though the proxy server')

    def do_GET(self):
        self.handel_request('GET')

    def do_POST(self):
        self.handel_request('POST')

    def handel_request(self, method: str):
        host, port = self.server.server_address
        if self.path == '/':
            self.config = MITM_CAHCE.get(self.server.domain)
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
            self._simple_headers(200, 'text/html; charset=utf-8')

            kwargs = dict(domain=self.path, sitekey=self.config.sitekey,
                          server=f"https://{host}:{port}")

            if self.config.kind == CaptchaKindEnum.RECAPTCHA_V3:
                kwargs['action'] = self.config.data_action

            self._render_template(self.config.kind.value + '.html', **kwargs)
        elif self.path.endswith('.pac'):
            domain = self.path[1:-4]
            self._simple_headers(200, 'text/plain; charset=utf-8')
            self._render_template('proxy.pac',
                                  host=host,
                                  port=port,
                                  domain=domain)
        elif self.path.startswith('/tokens'):
            self._simple_headers(200, 'text/json; charset=utf-8')
            self.wfile.write(
                json.dumps(tokens.to_list()).encode('utf-8'))
        elif self.path.startswith('/token'):
            if tokens.empty():
                self.send_error(
                    418, "I am a teapot and I have no tokens right now", 'Any attempt to brew coffee with a teapot should result in the error code "418 I\'m a teapot"')
            else:
                self._simple_headers(200, 'text/plain; charset=utf-8')
                self.wfile.write(tokens.get().encode('utf-8'))
        # elif self._find_config():

    def log_error(self, format, *args):
        log.error(format % args, extra={
            'timestamp': self.log_date_time_string(),
            'address': self.address_string()
        })

    def log_message(self, format, *args):
        log.info(format % args, extra={
            'timestamp': self.log_date_time_string(),
            'address': self.address_string()
        })


def setup(server_address: Tuple[str, int], domain: str, captcha_kind: CaptchaKindEnum, sitekey: str,
          data_action: str = None, keyfile: str = None, certfile: str = None) -> ThreadingHTTPServer:
    MITM_CAHCE[domain] = MITMRecord(captcha_kind, sitekey, data_action)
    httpd = ThreadingHTTPServer(server_address, ProxyHTTPRequestHandler)
    httpd.domain = domain
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   keyfile=keyfile or path.join(
                                       __dir__, 'server.key'),
                                   certfile=certfile or path.join(__dir__, 'server.crt'), server_side=True)
    return httpd


def serve(httpd: ThreadingHTTPServer):
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()


def start(server_address: Tuple[str, int], domain: str, captcha_kind: CaptchaKindEnum, sitekey: str,
          keyfile: str = None, certfile: str = None):
    httpd = setup(server_address, domain, captcha_kind, sitekey, keyfile,
                  certfile)
    serve(httpd)
