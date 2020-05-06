# CaptchaHarvester

> Solve captchas yourself without having to pay for services like 2captcha for use in automated projects.

## note

At the moment this project can be used for Google's V2 ReCaptchas and hCaptchas.

## setup

```bash
pip install captcha-harvester
```

## > harvester

This will setup an HTTP server at `http://127.0.0.1:5000` by default. This server is also
configured to proxy requests on whichever `DOMAIN` you pass it.

If you are running MacOS/Windows and have the [Brave Browser](https://brave.com/)
or [Google Chrome](https://www.google.com/chrome/), all you have to do is pass
the `-b/--browser` flag set to either `chrome` or `brave`. This will automatically open
a new instance of Brave/Chrome under a temporary profile with the proxy settings already
configured and loaded at the DOMAIN that was passed to the script. If you want to use
your main profile, you'll need to pass the `-r/--restart-browser` flag. To reconfigue
the proxy settings the browser will need to be restarted if it is already running.

If you aren't running MacOS/Windows then you'll need to install a proxy extension like
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

> If you would like to come up with an automated solution for your OS, I am open to PR requests.

```text
> harvester -h
usage: harvester [-h] -k SITE_KEY -d DOMAIN [-H HOST] [-p PORT]
                 [-b {chrome,brave}] [-r]
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
  -b {chrome,brave}, --browser {chrome,brave}
                        which browser to open on launch
  -r, --restart-browser
                        if this flag is not passed, a new instance of the
                        browser willbe opened. this flag is most helpful when
                        solving Googles ReCaptchasbecause if you restat your
                        main profile you'll most likely be loggedinto Google
                        and will be given an easier time on the captchas

For help contact @MacHacker#7322 (Discord)
```

## accessing the tokens

You can either access the tokens from another python project/process by using the
handy `fetch.token` function I included:

```python
from harvester import fetch

server_address = ('127.0.0.1', 5000)
token = fetch.token(server_address)
print('token:', token)
```

Or you can check out [example.py](example.py) to see how to progamatically
start the server and access the tokens by integrating the harvester with
your existsing (or new) code.

Additionally, if your other project isn't using Python, you can call `/token` which
will return one token and remove it from the Queue. If no tokens exists it will return
HTTP error code 418 "I'm a teapot."

## credits

Inspred by [Cosmo3904/Recaptcha-Harvester-V2](https://github.com/Cosmo3904/Recaptcha-Harvester-V2).

For help contact @MacHacker#7322 (Discord)

Has CaptchaHarvester saved you money on your project? Consider buying me a coffee!

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/noahcardoza)
