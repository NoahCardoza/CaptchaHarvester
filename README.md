# Recaptcha-Harvester-V2
# Solve Recaptcha Tokens for use in automated projects.

## Server.py
Server.py is a Flask Script that will run on port 5000 by default. Server.py is the only file in the project that requires the templates folder. This Script will recieve input from the harvester and store tokens for later use. Each token is only valid for 110 seconds and will be removed from the tokens list after expiring. The Tokens can be viewed in a web browser by visiting http://YOURIPHERE:5000/json

## Harvester.py
Harvester.py is a Selenium Script that can be automated for any project you use or it can be ran as a basic script (will ask for all the required input). The required inputs are the following fields: Sitekey, Domain, and Server IP. The optional inputs are Gmail Address and Gmail Password (This will just automate signing into google for ReCaptcha one-clicks). Sitekey is the ReCaptcha Sitekey you would like to harvest for, domain is the website that you are harvesting for, and serverip is the IP Address of the server that is running server.py. Server.py is required to store the tokens from the harvester, however it can be ran on the local machine if you point the harvester to localhost.

###### Automation Setup
```python
from Harvester import harvest
s = harvest('6Ld2sf4SAAAAAKSgzs0Q13IZhY02Pyo31S2jgOB5','http://patrickhlauke.github.io','127.0.0.1','me@gmail.com','gmailpasswordhere')
s.signin()
#When ready to solve do the below command
s.solve()
```
###### Basic Script Setup
```
Enter Sitekey : 6Ld2sf4SAAAAAKSgzs0Q13IZhY02Pyo31S2jgOB5
Solve For What Domain : http://patrickhlauke.github.io
What is the IP of the token server? : 127.0.0.1
Enter Gmail : me@gmail.com
Enter Gmail Password  : PASSWORDWILLENTERBLANKLY
```

## Fetch.py
Fetch.py is a Requests Script that will scrape your Token Server (Server.py) for an unused token, post it as a used token to the Token Server (Server.py) and return the token for use. Fetch.py is super easy to use and setup. Just simply run the 'main' function inside the script with the ip address of the Token Server (Server.py) as a parameter.
```python
from Fetch import main as getToken
serverIP = '127.0.0.1'
token = getToken(serverIP)
print('Token : ' + token)
```

# Leave me a follow on Twitter @Cosm00_!

