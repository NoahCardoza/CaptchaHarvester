# CaptchaHarvester

> Solve captchas yourself without having to pay for services like 2captcha for use in automated projects.

## setup

```bash
git clone https://github.com/NoahCardoza/CaptchaHarvester
cd CaptchaHarvester
pipenv install
```

> NOTE: Make sure you have the [chromedriver](https://sites.google.com/a/chromium.org/chromedriver/downloads) for Selenium in your PATH.

## > harvester

```bash
> python harvester -h
usage: harvester [-h] {harvest,server,fetch} ...

positional arguments:
  {harvest,server,fetch}

optional arguments:
  -h, --help            show this help message and exit
```

## > harvester server

Runs a Flask server on port 5000 by default. This server will recieve input from the harvester and store tokens for later use. Each token is only valid for 110 seconds and will be removed from the tokens list after expiring. The Tokens can be viewed in a web browser by visiting `http://localhost:5000/json`.

```bash
> python harvester server -h
usage: harvester server [-h] [-p PORT]

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  defaults to 5000
```

## > harvester harvest

This will use Selenium and navigate to the domain and allow you to solve captchas yourself that will be sent to the server which you can access from your application later.

At the moment this project can be used for Google's V2 ReCaptchas and hCaptchas.

```bash
> python harvester harvest -h
usage: harvester harvest [-h] -k SITE_KEY -d DOMAIN [-s TOKEN_SERVER]
                         [-g GMAIL_EMAIL]
                         {recaptcha,hcaptcha}

positional arguments:
  {recaptcha,hcaptcha}

optional arguments:
  -h, --help            show this help message and exit
  -k SITE_KEY, --site-key SITE_KEY
  -d DOMAIN, --domain DOMAIN
  -s TOKEN_SERVER, --token-server TOKEN_SERVER
  -g GMAIL_EMAIL, --gmail-email GMAIL_EMAIL
```

## accessing the tokens

```python
from harvester.fetch import getToken
token = getToken('localhost:5000')
print('Token : ' + token)
```

## credits

Originally based off [Cosmo3904/Recaptcha-Harvester-V2](https://github.com/Cosmo3904/Recaptcha-Harvester-V2).

Has CaptchaHarvester saved you money on your project? Consider buying me a coffee!

  [![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/noahcardoza)
