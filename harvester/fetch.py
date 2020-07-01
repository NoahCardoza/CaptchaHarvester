import ssl
from urllib.request import urlopen, HTTPError
from time import sleep
from typing import Tuple


def token(server_address: Tuple[str, int], timeout=3) -> str:
    url = f'https://{server_address[0]}:{server_address[1]}/token'
    context = ssl.SSLContext()
    while 1:
        try:
            return urlopen(url, context=context).read().decode('ascii')
        except HTTPError:
            sleep(timeout)


if __name__ == '__main__':
    server_address = ('127.0.0.1', 5000)
    print(token(server_address))
