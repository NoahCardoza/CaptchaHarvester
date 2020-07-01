# CaptchaHarvester

> Solve captchas yourself without having to pay for services like 2captcha for use in automated projects.

## note

At the moment this project can be used for Google's V2 and V3 ReCaptchas and hCaptchas.

## setup

### PyPi

```bash
pip install captcha-harvester
```

### The `dev` branch

Sometimes there will be updates I'm working on that won't be pushed to the master branch/PyPi
because I haven't had time to test them. Sometimes these patches will fix problems you experience
in the stable branch, but if things get buggy don't be surprised.

```bash
pip install https://github.com/NoahCardoza/CaptchaHarvester/archive/dev.zip
```

## > harvester

This will setup an HTTP server at `https://127.0.0.1:5000` by default.

If you are running MacOS/Windows and have the [Brave Browser](https://brave.com/)
or [Google Chrome](https://www.google.com/chrome/), all you have to do is pass
the `-b/--browser` flag set to either `chrome` or `brave`. This will automatically open
a new instance of Brave/Chrome under a temporary profile with and map the `domain` to the
local server.

> If you would like to come up with an automated solution for your OS, I am open to PR requests.

```text
> harvester -h
usage: harvester.py [-h] -k SITE_KEY -d DOMAIN [-H HOST] [-p PORT]
                    [-b {chrome,brave}] [-r] [-v]
                    {recaptcha-v2,recaptcha-v3,hcaptcha}

CaptchaHarvester: Solve captchas yourself without having to pay for services
like 2captcha for use in automated projects.

positional arguments:
  {recaptcha-v2,recaptcha-v3,hcaptcha}
                        the type of captcha you are want to solve

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
  -v, --verbose         show more logging

For help contact @MacHacker#7322 (Discord)
```

## v2 vs. v3

When solving Google's v3 captchas, you should login to a Google Account first. The v3 captcha's
work of a raiting system of your browsing habits. They are a little finicky compared to their v2
predecessors. If the tokens stop working, you should start using a different Google Account or
wait a little bit between relaoding the captcha harvester page.

## accessing the tokens

You can either access the tokens from another python project/process by using the
handy `fetch.token` function I included:

```python
from harvester import fetch

server_address = ('127.0.0.1', 5000)
token = fetch.token(server_address)
print('token:', token)
```

**Alternativly**:
You can check out [example.py](example.py) to see how to progamatically
start the server and access the tokens by integrating the harvester with
your existsing (or new) code.

Additionally, if your other project isn't using Python, you can call `/token` which
will return one token and remove it from the Queue. If no tokens exists it will return
HTTP error code 418 "I'm a teapot."

**NOTE**: if you are making requests from another program, you'll get SSL errors
because the server isn't really who it claims to be. Make sure you configure your
program to ignore these errors.

## credits

Inspred by [Cosmo3904/Recaptcha-Harvester-V2](https://github.com/Cosmo3904/Recaptcha-Harvester-V2).

For help contact @MacHacker#7322 (Discord)

Has CaptchaHarvester saved you money on your project? Consider buying me a coffee!

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/noahcardoza)
