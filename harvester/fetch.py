import time
from urllib.request import HTTPError, urlopen


def token(domain: str, host: str = '127.0.0.1', port: int = 5000, sleep=3) -> str:
    url = f'http://{host}:{port}/{domain}/token'
    while 1:
        try:
            return urlopen(url).read().decode('ascii')
        except HTTPError:
            time.sleep(sleep)


if __name__ == '__main__':
    server_address = ('127.0.0.1', 5000)
    print(token('www.sneakersnstuff.com', *server_address))
