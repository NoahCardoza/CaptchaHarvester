import server
import argparse

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
args = ap.parse_args()

print(f'server running on http://{args.host}:{args.port}')
server.start(args.host, args.port, args.domain, args.type, args.site_key)
