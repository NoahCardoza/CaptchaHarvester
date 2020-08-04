import argparse
import logging
from threading import Thread
import sys
from . import server, browser
from .server import CaptchaKindEnum, tokens
from .browser import BrowserEnum


def entry_point():
    ap = argparse.ArgumentParser(
        description='CaptchaHarvester: Solve captchas yourself without having to pay for services like 2captcha for use in automated projects.',
        epilog='For help contact @MacHacker#7322 (Discord)')
    ap.add_argument('type', choices=['recaptcha-v2', 'recaptcha-v3', 'hcaptcha'],
                    help='The type of captcha that that that domain/sitekey pair is for.')
    ap.add_argument('-a', '--data-action',
                    help='Sets the action in rendered recaptcha-v3 when'
                    ' collecting tokens (required with recaptcha-v3)', default=None)
    ap.add_argument('-k', '--site-key', required=True,
                    help='The sitekey used by the captcha.')
    ap.add_argument('-d', '--domain', required=True,
                    help='The domain of the site which hosts the captcha you want to solve.')
    ap.add_argument('-H', '--host', help='Defaults to 127.0.0.1.',
                    default='127.0.0.1')
    ap.add_argument('-p', '--port', help='Defaults to 5000.',
                    default=5000, type=int)

    ap.add_argument('-b', '--browser',
                    help='Which browser to open on launch. Quick options are chrome/brave, '
                    'but you can also pass the path to any Chromium browser.')
    ap.add_argument('-r', '--restart-browser',
                    help='If this flag is not passed, a new instance of the browser will'
                    ' be opened. this flag is most helpful when solving Googles ReCaptchas'
                    ' because if you restat your main profile you\'ll most likely be logged'
                    ' into Google and will be given an easier time on the captchas.', default=False, action='store_true')
    ap.add_argument('-e', '--load-extension',
                    help='Loads unpacked extensions when starting the browser,'
                    ' to load multiple extensions sepparate the paths with commas'
                    ' (must be used with -b/--browser).', default=None)
    ap.add_argument('-v', '--verbose',
                    help='Show more server and browser (when using -b/--browser) logging.', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        log = logging.getLogger('harvester')
        log.setLevel(logging.INFO)

    if args.load_extension and not args.browser:
        ap.error('cannot use -e/--load-extension without -b/--browser')

    if args.type == 'recaptcha-v3' and not args.data_action:
        ap.error('recaptcha-v3 requires the -a/--data_action parameter')

    print(f'server running on https://{args.host}:{args.port}')

    server_address = (args.host, args.port)

    httpd = server.setup(server_address, args.domain,
                         server.CaptchaKindEnum(args.type), args.site_key, data_action=args.data_action)

    server_thread = Thread(target=server.serve, daemon=True, args=(httpd,))
    server_thread.start()

    try:
        if args.browser:
            browser_thread = browser.launch(args.domain, httpd.server_address,
                                            browser=args.browser, restart=args.restart_browser,
                                            extensions=args.load_extension, verbose=args.verbose)
            if sys.platform[:3] == 'win':
                # since I don't know how to locate the binary on windows
                # we can't join the thread because we are starting the browser
                # with start which doens't connect to the proccess
                from time import sleep
                try:
                    while 1:
                        sleep(1000)
                except KeyboardInterrupt:
                    pass
            else:
                browser_thread.join()
        else:
            server_thread.join()
    except KeyboardInterrupt:
        pass
