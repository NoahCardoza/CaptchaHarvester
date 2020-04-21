import server
import argparse

ap = argparse.ArgumentParser()
ap.add_argument('type', choices=['recaptcha', 'hcaptcha'])
ap.add_argument('-k', '--site-key', required=True)
ap.add_argument('-d', '--domain', required=True)
ap.add_argument('-H', '--host', help='defaults to 127.0.0.1',
                default='127.0.0.1')
ap.add_argument('-p', '--port', help='defaults to 5000',
                default=5000, type=int)
args = ap.parse_args()

print(f'server running on http://{args.host}:{args.port}')
server.start(args.host, args.port, args.domain, args.type, args.site_key)
