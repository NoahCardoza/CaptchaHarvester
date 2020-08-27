# programatic example showing how to access the harvester api from
# within your own script without having to use the fetch module

import logging
from threading import Thread

from harvester import Harvester

# silence server logs
logging.getLogger('harvester').setLevel(logging.CRITICAL)

# first we create a harvester instance
harvester = Harvester()
"""
if we wanted it to run on another host/port:
harvester = Harvester('0.0.0.0', 7777)

---

then we add an intercepter
"""
tokens = harvester.intercept_hcaptcha(
    domain='www.sneakersnstuff.com',
    sitekey='33f96e6a-38cd-421b-bb68-7806e1764460')
"""
we can also intercept recaptchas!
    tokens = harvester.intercept_recaptcha_v2(domain, sitekey)
    tokens = harvester.intercept_recaptcha_v3(domain, sitekey, action)

P.S. we can also add multiple intercepts at a time to harvest tokens
     for multiple domains at a time

harvester.intercept_* returns a queue of the tokens what get solve by
said intercepter

additionally, if we want to access the queues else where we can use
    harvester.get_token_queue(domain)

---

next, we can run the server in a separate thread to keep from
blocking the rest of the program
"""
server_thread = Thread(target=harvester.serve, daemon=True)
server_thread.start()

# launch a browser instance where we can solve the captchas
harvester.launch_browser()
"""
there are a bunch of extra arguments you can pass to tune things exactly how you want then:
    browser: Union[browserModule.BrowserEnum, str] = browserModule.BrowserEnum.CHROME 
    restart: bool = False
    width: int = 400
    height: int = 580
    args: List[str] = []
    extensions: str = None
    verbose: bool = False
"""

try:
    while True:
        # block until we get sent a captcha token and repeat
        token = tokens.get()
        print('we just recived a token:', token)
except KeyboardInterrupt:
    pass
