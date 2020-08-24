![CaptchaHarvester](logo.png)

# CaptchaHarvester

> Solve captchas yourself without having to pay for services like 2captcha for use in automated projects.

## Discord

If you need help feel free to swing by my [Discord](https://discord.gg/AAQrkhR)!

## Use Cases

This project allows you to solve Google's V2 and V3 ReCaptchas as well as
hCaptchas. However, since Google's V3 ReCaptchas are based on a rating
system of your browser and browsing habits, it's slightly less reliable.

### [CloudProxy](https://github.com/NoahCardoza/CloudProxy)

This project is also natively supported by a newer project of mine which allows you to bypass
Cloudflare's Bot Detection. It's super simlpe to setup, just follow the instructions [here](https://github.com/NoahCardoza/CloudProxy#harvester).

## Setup

### PyPi

```bash
pip install captcha-harvester
```

### The `dev` Branch

Sometimes there will be updates I'm working on that won't be pushed to the master branch/PyPi
because I haven't had time to test them. Sometimes these patches will fix problems you experience
in the stable branch, but if things get buggy don't be surprised.

```bash
pip install https://github.com/NoahCardoza/CaptchaHarvester/archive/dev.zip
```

## Usage

## > harvester

This will setup an HTTP server at `https://127.0.0.1:5000` by default.

If you are running MacOS/Windows and have the [Brave Browser](https://brave.com/)
or [Google Chrome](https://www.google.com/chrome/), all you have to do is pass
the `-b/--browser` flag set to either `chrome` or `brave`. This will automatically open
a new instance of Brave/Chrome under a temporary profile with and map the `domain` to the
local server.

**NOTE**: Without the `-b/--browser` only the server will start up, without the browser. You won't
be able to access the site correctly on your normal browsers because the host won't be correctly
mapped to the local server. This could be useful if you want to open the browser with your own
command line options or you already have one running from a previous session.

> If you would like to come up with an automated solution for your OS, I am open to PR requests.

```text
> harvester -h
usage: harvester.py [-h] [-a DATA_ACTION] -k SITE_KEY -d DOMAIN [-H HOST]
                    [-p PORT] [-b BROWSER] [-B] [-r] [-e LOAD_EXTENSION] [-v]
                    {recaptcha-v2,recaptcha-v3,hcaptcha}

CaptchaHarvester: Solve captchas yourself without having to pay for services
like 2captcha for use in automated projects.

positional arguments:
  {recaptcha-v2,recaptcha-v3,hcaptcha}
                        The type of captcha that that that domain/sitekey pair
                        is for.

optional arguments:
  -h, --help            show this help message and exit
  -a DATA_ACTION, --data-action DATA_ACTION
                        Sets the action in rendered recaptcha-v3 when
                        collecting tokens (required with recaptcha-v3)
  -k SITE_KEY, --site-key SITE_KEY
                        The sitekey used by the captcha.
  -d DOMAIN, --domain DOMAIN
                        The domain of the site which hosts the captcha you
                        want to solve.
  -H HOST, --host HOST  Defaults to 127.0.0.1.
  -p PORT, --port PORT  Defaults to 5000.
  -b BROWSER, --browser BROWSER
                        Allows you to pass the path to any Chromium browser.
  -B, --no-browser      Keeps the harvester from launching a browser br
                        default.
  -r, --restart-browser
                        If this flag is not passed, a new instance of the
                        browser will be opened. this flag is most helpful when
                        solving Googles ReCaptchas because if you restat your
                        main profile you'll most likely be logged into Google
                        and will be given an easier time on the captchas.
  -e LOAD_EXTENSION, --load-extension LOAD_EXTENSION
                        Loads unpacked extensions when starting the browser,
                        to load multiple extensions sepparate the paths with
                        commas (must be used with -b/--browser).
  -v, --verbose         Show more server and browser (when using -b/--browser)
                        logging.

For help contact @MacHacker#7322 (Discord)
```

## Configuring The Browser

When accessing the server to collect the tokens you have to do it the right way and you can't connect to it
just like any old server. You configure your browser to think that the server is actually the site we want
to collect captcha tokens for

### How do we do this the EASY way?

Luckily, the easy way is pretty easy. You literally have to do nothing! However, this only works on Mac/Windows (Linux
support coming soon). Additionally, you can pass the path to a **Chromium** browser binary/`.exe` or a browser
that can be found in your $PATH envrionment variable through the `-b/--browser`.

When using the `-b`, a browser instance will be lanuched that's totally disconnected from your main Profile
(unless you pass `-r`, which *MIGHT* be buggy on Windows).

**NOTE**: The way the harvester is currently setup, if you use the `-b` flag to start up the browser, then when you quit either the browser or the server, the other will also terminate.

### How do we do this the HARD way?

Mainly through the use on the `--host-rules` Chromium flag. Here's an example:

```bash
--host-rules="MAP example.com 127.0.0.1:5000"
```

Basically this sets the DNS record for `example.com` to `127.0.0.1:5000` rather than querying a DNS server
for the actual IP of the real site. This helps us trick the captcha provider into thinking that the captcha
is actually being loaded on their client's.

There are a few other arguments the harvester uses to make things easier and simpler which can be found in
[/harvester/browser.py](https://github.com/NoahCardoza/CaptchaHarvester/blob/master/harvester/browser.py).

If for some reason you don't want a browser launched on the start of the harvester or you want to configure it
youself, all you have to do is pass the `-b/--no-browser` flag.

## Solveing V2 Captchas with [Buster](https://github.com/dessant/buster)

You might find it useful to use [Buster](https://github.com/dessant/buster) when solving V2 Captchas.
You can clone and build the extension for chrome, and then pass the path of the built extension
to harvester with the `-e/--load-extension` flag.

## ReCaptcha: V2 vs. V3

When solving Google's v3 captchas, you should login to a Google Account first. The v3 captcha's
work of a raiting system of your browsing habits. They are a little finicky compared to their v2
predecessors. If the tokens stop working, you should start using a different Google Account or
wait a little bit between reloading the captcha harvester page.

Additonally, V3 ReCaptcha's require an action when submitting the captcha. Sometimes they don't
matter if the target site dosen't double check them and you can get away passing anything to (-a/--data-action).
However, it is advised that you grab the correct `data-action` attribute when looking for the sitekey, they
should be near each other.

## How do I use the tokens of the captcha's I solve?

### API

In most cases you'll probably want to use the API to fetch the tokens.

#### Python

If you want to access the tokens with a Python script, you are in luck! I've included a handy
wrapper for the API which makes things really simple. Just take a look at this example:

```python
from harvester import fetch

# assuming we ran: harvester recaptcha-v2 -d guerrillamail.com -k 6LcIHdESAAAAALVQtprzwjt2Rq722tkxk-RDQ0aN
token = fetch.token('guerrillamail.com')
print('Token:', token)

# assuming we ran: harvester recaptcha-v2 -d guerrillamail.com -k 6LcIHdESAAAAALVQtprzwjt2Rq722tkxk-RDQ0aN -p 8888
token = fetch.token('guerrillamail.com', port=8888)
print('Token:', token)
```

#### Any Other Lanuage (via HTTP API)

If your lanuage of choice isn't Python, then you can grab tokens by making calls to the API endpoints
that the harvester's server has avalible.

Route | Type | Description
| :--- | :--- | :--- |
 `/<domain>/token` | String | This is your most useful endpoint. When called it will pop a token from the queue and return it in plain text. If no tokens are available it will return a [418 status code](https://httpstatuses.com/418).
 `/<domain>/tokens` | List\[String\] | This will return a list of all the avalible tokens in the queue. It is recomended that you never use any tokens you see in this list because then `/token` may return an already used token.

Where `<domain>` is the domain the harvester was lanuched on. We need this because the harvester supports intercepting multiple domains at a time.

### Programtically

You can check out [example.py](example.py) to see how to progamatically
start the server and access the tokens by integrating the harvester with
your existsing (or new) code.

The main advantage of setting up the harvester programtically is you can
set multiple interccepter hooks to solve captchas on multiple domains.

## PyArmor/PyInstaller

If you are using this project with PyArmor and or PyInstaller then fear not, it has
already been configured to work seamlessly when packages into an `.exe` file. All you
have to do is add the following to your `.spec` file's `Anaysis` call.

```py
Anaysis(datas=[
  ("icon.png", r"harvester\server"),
  ("hcaptcha.html", r"harvester\server\templates"),
  ("recaptcha-v2.html", r"harvester\server\templates"),
  ("recaptcha-v3.html", r"harvester\server\templates"),
  ("domains.html", r"harvester\server\templates")
])
```

## Credits

Inspred by [Cosmo3904/Recaptcha-Harvester-V2](https://github.com/Cosmo3904/Recaptcha-Harvester-V2).

For help contact @`MacHacker#7322` (Discord)

Has CaptchaHarvester saved you money on your project? Consider buying me a coffee for the countless hours I have
spent making your job easier?

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/noahcardoza)

Made with ❤️ by [@NoahCardoza](https://github.com/NoahCardoza)
