import harvester
from harvester import CaptchaKindEnum, BrowserEnum
from threading import Thread, Timer
import logging

# programatic example showing how to access the harvester api from
# within your own script without having to use the fetch module

# setup defaults
server_address = ('127.0.0.1', 5000)
domain = 'www.sneakersnstuff.com'
sitekey = '33f96e6a-38cd-421b-bb68-7806e1764460'

# silence server logs
logging.getLogger('harvester').setLevel(logging.CRITICAL)

# run the server in a separate thread to keep from
# blocking the rest of the program
server_thread = Thread(target=harvester.server.start,
                       args=(server_address, domain,
                             CaptchaKindEnum.HCAPTCHA, sitekey),
                       daemon=True)
server_thread.start()

# launch a browser instance where we can solve the captchas
harvester.browser.launch(domain, server_address, BrowserEnum.CHROME)

try:
    while True:
        # block until we get sent a captcha token and repeat
        token = harvester.tokens.get()
        print('we just recived a token:', token)
except KeyboardInterrupt:
    pass
