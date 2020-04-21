from requests import get
from time import sleep


# TODO: MAYBE convert to iteratoer/class?
def getToken(host, timeout=3):
    uri = 'http://' + host + '/token'
    res = get(uri)
    while True:
        if res.ok():
            return res.text
        sleep(timeout)
        res = get(uri)
