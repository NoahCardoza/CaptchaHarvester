import argparse
import logging
from . import server, browser
from .server import CaptchaKindEnum, tokens
from .browser import BrowserEnum


def entry_point():
    ap = argparse.ArgumentParser(
        description='CaptchaHarvester: Solve captchas yourself without having to pay for services like 2captcha for use in automated projects.',
        epilog='For help contact @MacHacker#7322 (Discord)')
    ap.add_argument('type', choices=['recaptcha', 'hcaptcha'],
                    help='the type of captcha you are want to solve')
    ap.add_argument('-k', '--site-key', required=True,
                    help='the sitekey used by the captcha on page')
    ap.add_argument('-d', '--domain', required=True,
                    help='the domain for which you want to solve captchas')
    ap.add_argument('-H', '--host', help='defaults to 127.0.0.1',
                    default='127.0.0.1')
    ap.add_argument('-p', '--port', help='defaults to 5000',
                    default=5000, type=int)

    ap.add_argument('-b', '--browser',
                    help='which browser to open on launch', choices=['chrome', 'brave'])
    ap.add_argument('-r', '--restart-browser',
                    help='if this flag is not passed, a new instance of the browser will'
                    'be opened. this flag is most helpful when solving Googles ReCaptchas'
                    'because if you restat your main profile you\'ll most likely be logged'
                    'into Google and will be given an easier time on the captchas', default=False, action='store_true')
    ap.add_argument('-v', '--verbose',
                    help='show more logging', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        log = logging.getLogger('harvester')
        log.setLevel(logging.INFO)

    print(f'server running on http://{args.host}:{args.port}')

    server_address = (args.host, args.port)

    httpd = server.setup(server_address, args.domain,
                         server.CaptchaKindEnum(args.type), args.site_key)

    if args.browser:
        browser.launch(args.domain, httpd.server_address,
                       browser=browser.BrowserEnum(args.browser), restart=args.restart_browser)

    server.serve(httpd)
