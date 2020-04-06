import requests
import json

tokens = []


# TODO: convert to iteratoer/class
def getToken(host):
    host = 'http://' + host
    s = requests.Session()
    json_dict = s.get(host + '/json').json()
    index = 0
    capToken = 'temp'
    while True:
        try:
            capToken = json_dict['tokens'][index]
        except IndexError:
            index = 0
            json_dict = s.get(host + '/json').json()
        if capToken in tokens or capToken in json_dict['used']:
            index = index + 1
        elif capToken == 'temp':
            pass
        elif capToken == '':
            index = index + 1
        else:
            tokens.append(capToken)
            s.post(host + '/used',
                   data={'usedtoken': capToken})
            return(capToken)
