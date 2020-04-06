import argparse
import getpass
from os import path

import server
from harvester import Harvest, load_html_template

argparser = argparse.ArgumentParser()
subparser = argparser.add_subparsers(
    dest='command', required=True)

hp = subparser.add_parser('harvest')
hp.add_argument('type', choices=['recaptcha', 'hcaptcha'])
hp.add_argument('-k', '--site-key', required=True)
hp.add_argument('-d', '--domain', required=True)
hp.add_argument('-s', '--token-server',
                help='defaults to localhost:5000', default='localhost:5000')
hp.add_argument('-g', '--gmail-email')

sp = subparser.add_parser('server')
sp.add_argument('-p', '--port', help='defaults to 5000',
                default=5000, type=int)

fp = subparser.add_parser('fetch')
fp.add_argument('-s', '--token-server', default='localhost:5000')

args = argparser.parse_args()

if args.command == 'harvest':
    html_template = load_html_template(
        args.type, args.site_key, args.token_server)

    s = Harvest(args.domain, html_template)
    if args.gmail_email:
        gmail_email_password = getpass.getpass('> Gmail Password: ')
        s.signin(args.gmail_email, gmail_email_password)
        input('> Press Enter to Begin Solving...')

    while True:
        s.solve()
elif args.command == 'server':
    server.start(args.port)
elif args.command == 'fetch':
    print('err: still under construction')
