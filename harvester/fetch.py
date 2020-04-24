import urllib3
from time import sleep
from typing import Tuple


def token(server_address: Tuple[str, int], timeout=3) -> str:
    url = f'http://{server_address[0]}:{server_address[1]}/token'
    http = urllib3.PoolManager()
    res = http.request('GET', url)
    while res.status != 200:
        print(res, res.status, res.data)
        sleep(timeout)
        res = http.request('GET', url)
    return res.data.decode('ascii')


if __name__ == '__main__':
    server_address = ('127.0.0.1', 5000)
    print(token(server_address))
