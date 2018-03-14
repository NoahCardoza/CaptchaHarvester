import requests, json

tokens = []

def main(ipaddress):
    global Tokens
    s = requests.Session()
    while True:
        try:
            res = s.get('http://'+ipaddress+':5000/json')
            break
        except:
            pass
    json_dict = res.json()
    index = 0
    capToken = 'temp'
    while True:
        try:
            capToken = json_dict['tokens'][index]
        except IndexError:
            index = 0
            while True:
                try:
                    res = s.get('http://'+ipaddress+':5000/json')
                    break
                except:
                    pass
            json_dict = res.json()
            pass
        if capToken in tokens or capToken in json_dict['used']:
            index = index + 1
        elif capToken == 'temp':
            pass
        elif capToken == '':
            index = index + 1
        else:
            tokens.append(capToken)
            s.post('http://'+ipaddress+':5000/used', data = {'usedtoken':capToken})
            return(capToken)
