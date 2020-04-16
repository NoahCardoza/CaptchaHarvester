from threading import Thread
import time
from proxy.http.codes import httpStatusCodes
from proxy.common.utils import build_http_response
from proxy.plugin import ManInTheMiddlePlugin
from urllib.parse import parse_qs
import store


def my_render_template(file, **args):
    with open('templates/' + file, 'r') as f:
        template = f.read()
        for k, v in args.items():
            template = template.replace('{{ ' + k + ' }}', v)
    return template


class MyManInTheMiddlePlugin(ManInTheMiddlePlugin):
    overwrite = None

    def before_upstream_connection(self, request):
        host = request.url.netloc.decode()
        if host in store.host_map:
            if request.method == b'POST':
                body = parse_qs(request.body)
                token = body.get(
                    b'g-recaptcha-response') or body.get(b'h-captcha-response')
                if token:
                    token = token[0].decode()
                    store.tokens.put(token)
            self.overwrite = host
        return request

    def handle_upstream_chunk(self, chunk: memoryview):
        if self.overwrite:
            config = store.host_map[self.overwrite]
            return memoryview(build_http_response(
                httpStatusCodes.OK,
                reason=b'OK',
                body=my_render_template(config['type'] + '.html', sitekey=config['sitekey']).encode()))
        return chunk
