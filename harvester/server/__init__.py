import json
import cgi
from os import path
from enum import Enum
from urllib import parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .expiring_queue import ExpiringQueue
from queue import Queue
from dataclasses import dataclass
from typing import Dict, Union, Tuple, List
import logging
import sys
import shutil
import harvester.browser as browserModule
import re

domain_pattern = re.compile(
    r'^(?:[a-zA-Z0-9]'  # First character of the domain
    r'(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)'  # Sub domain + hostname
    r'+[A-Za-z0-9][A-Za-z0-9-_]{0,61}'  # First 61 characters of the gTLD
    r'[A-Za-z]$'  # Last character of the gTLD
)


log = logging.getLogger('harvester')
sh = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    '%(name)s(%(levelname)s) [%(timestamp)s] [%(address)s] %(message)s')
sh.setFormatter(formatter)
log.addHandler(sh)


class DomainInvalidException(Exception):
    pass


class CaptchaKindEnum(Enum):
    HCAPTCHA = 'hcaptcha'
    RECAPTCHA_V2 = 'recaptcha-v2'
    RECAPTCHA_V3 = 'recaptcha-v3'


@dataclass
class MITMRecord:
    kind: CaptchaKindEnum
    sitekey: str
    data_action: str
    tokens: 'ExpiringQueue[str]' = ExpiringQueue(110)


# support for pyarmor/pyinstaller
__dir__ = path.join(getattr(sys, '_MEIPASS'), 'harvester', 'server') if getattr(
    sys, '_MEIPASS', None) else path.abspath(path.dirname(__file__))


def ProxyHTTPRequestHandlerWrapper(domain_cache: Dict[str, MITMRecord] = {}):
    class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
        config: MITMRecord
        domain: str

        def _render_template(self, file: str, **args: Dict[str, Union[str, int]]):
            with open(path.join(__dir__, 'templates', file), 'r', encoding='utf-8') as f:
                template = f.read()
            for k, v in args.items():
                template = template.replace('{{ ' + k + ' }}', str(v))

            self.wfile.write(template.encode('utf-8'))

        def _find_config(self):
            self.domain = self.headers.get('host', None)
            self.config = domain_cache.get(self.domain, None)
            if not self.config:
                self.domain, path = self.path.strip('/').split('/', 1)
                self.path = '/' + path
                self.config = domain_cache.get(self.domain, None)
                if not self.config:
                    self.send_error(404, 'Not intercepted',
                                    'This either happend because you are trying to solve captchas on localhost or you didn\'t configure the'
                                    ' harvester to harvest on the domain you are trying to access the harvester through.')
                    return False
            return True

        def _simple_headers(self, code: int, content_type: str):
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.end_headers()

        def do_CONNECT(self):
            self.send_error(
                500, "Yuck! hTtPs", 'Make sure to use http:// not https:// when accessing the host though the proxy server')

        def do_GET(self):
            if self.path == '/favicon.ico':
                self._simple_headers(200, 'image/png')
                shutil.copyfileobj(
                    open(path.join(__dir__, 'icon.png'), 'rb'), self.wfile)
            elif self.path == '/style.css':
                self._simple_headers(200, 'text/css')
                shutil.copyfileobj(
                    open(path.join(__dir__, 'style.css'), 'rb'), self.wfile)
            elif self.path == '/domains':
                self._simple_headers(200, 'text/html')
                domain_list = ''
                for domain in domain_cache.keys():
                    domain_list += f'<li class="list-group-item"><a href="http://{domain}">{domain}</a></li>'
                self._render_template('domains.html', domain_list=domain_list)
            else:
                self.handel_request('GET')

        def do_POST(self):
            self.handel_request('POST')

        def handel_request(self, method: str):
            if self._find_config():
                host, port = self.server.server_address
                if self.path == '/':
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
                            self.config.tokens.put(token)
                    self._simple_headers(200, 'text/html; charset=utf-8')

                    kwargs = dict(domain=self.domain, sitekey=self.config.sitekey,
                                  server=f"http://{host}:{port}")

                    if self.config.kind == CaptchaKindEnum.RECAPTCHA_V3:
                        kwargs['action'] = self.config.data_action

                    self._render_template(
                        self.config.kind.value + '.html', **kwargs)
                elif self.path.startswith('/tokens'):
                    self._simple_headers(200, 'text/json; charset=utf-8')
                    self.wfile.write(
                        json.dumps(self.config.tokens.to_list()).encode('utf-8'))
                elif self.path.startswith('/token'):
                    if self.config.tokens.empty():
                        self.send_error(
                            418, "I am a teapot and I have no tokens right now", 'Any attempt to brew coffee with a teapot should result in the error code "418 I\'m a teapot"')
                    else:
                        self._simple_headers(200, 'text/plain; charset=utf-8')
                        self.wfile.write(
                            self.config.tokens.get().encode('utf-8'))

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
    return ProxyHTTPRequestHandler


class Harvester(object):
    def __init__(self, host='127.0.0.1', port=5000):
        self.domain_cache: Dict[str, MITMRecord] = {}
        self.httpd = ThreadingHTTPServer(
            (host, port), ProxyHTTPRequestHandlerWrapper(self.domain_cache))

    def serve(self):
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.httpd.shutdown()

    def launch_browser(self, browser: Union[browserModule.BrowserEnum, str] = browserModule.BrowserEnum.CHROME,
                       restart: bool = False, width: int = 400, height: int = 580, args: List[str] = [],
                       extensions: str = None, verbose: bool = False):
        return browserModule.launch(list(self.domain_cache.keys()),
                                    self.httpd.server_address, browser, restart, width, height, args, extensions, verbose)

    def get_token_queue(self, domain):
        return self.domain_cache[domain].tokens

    def _intercept(self, domain: str, sitekey: str, captcha_kind: CaptchaKindEnum, action: str = None):
        if not domain_pattern.match(domain):
            raise DomainInvalidException(
                'You must only give a domain, not a whole URL.')
        ret = self.domain_cache[domain] = MITMRecord(
            captcha_kind, sitekey, action)
        return ret

    def intercept_recaptch_v2(self, domain: str, sitekey: str):
        return self._intercept(domain, sitekey, CaptchaKindEnum.RECAPTCHA_V2, None)

    def intercept_recaptch_v3(self, domain: str, sitekey: str, action: str = None):
        return self._intercept(domain, sitekey,
                               CaptchaKindEnum.RECAPTCHA_V3, action=action)

    def intercept_hcaptcha(self, domain: str, sitekey: str):
        return self._intercept(domain, sitekey, CaptchaKindEnum.HCAPTCHA, None)
