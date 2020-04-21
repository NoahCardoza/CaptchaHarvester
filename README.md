# CaptchaHarvester

> Solve captchas yourself without having to pay for services like 2captcha for use in automated projects.

## note

At the moment this project can be used for Google's V2 ReCaptchas and hCaptchas.

## setup

```bash
git clone https://github.com/NoahCardoza/CaptchaHarvester
cd CaptchaHarvester
pipenv install
```

## > harvester

This will setup an HTTP server at `http://127.0.0.1:5000` by default. This server is also
configured to proxy requests on whichever `DOMAIN` you pass it. Next, install an extention like
[Proxy Switcher and Manager](https://chrome.google.com/webstore/detail/proxy-switcher-and-manage/onnfghpihccifgojkpnnncpagjcdbjod?hl=en)
that supports **PAC Scripts**. Use a script like:

```js
function FindProxyForURL(url, host) {
  if (host == 'DOMAIN')
    return 'PROXY HOST:PORT';
  return 'DIRECT';
}
```

This will make sure that all traffic sent to `DOMAIN` will be proxied by our server and it
will return one of the template files rather than actually contact the `DOMAIN` server.

```text
> python harvester -h
usage: harvester [-h] -k SITE_KEY -d DOMAIN [-H HOST] [-p PORT]
                 {recaptcha,hcaptcha}

CaptchaHarvester: Solve captchas yourself without having to pay for services
like 2captcha for use in automated projects.

positional arguments:
  {recaptcha,hcaptcha}  the type of captcha you are want to solve

optional arguments:
  -h, --help            show this help message and exit
  -k SITE_KEY, --site-key SITE_KEY
                        the sitekey used by the captcha on page
  -d DOMAIN, --domain DOMAIN
                        the domain for which you want to solve captchas
  -H HOST, --host HOST  defaults to 127.0.0.1
  -p PORT, --port PORT  defaults to 5000

For help contact @MacHacker#7322 (Discord)
```

## accessing the tokens

```python
from harvester.fetch import getToken
token = getToken('localhost:5000')
print('Token:', token)
```

## credits

Inspred by [Cosmo3904/Recaptcha-Harvester-V2](https://github.com/Cosmo3904/Recaptcha-Harvester-V2).

For help contact @MacHacker#7322 (Discord)

Has CaptchaHarvester saved you money on your project? Consider buying me a coffee!

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/noahcardoza)
