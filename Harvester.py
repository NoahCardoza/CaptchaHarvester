# Code Written by @Cosm00_
# Stay Based Youngins....

from selenium import webdriver
import time, getpass, selenium
from selenium.webdriver.chrome.options import Options


class harvest:
    def __init__(self, sitekey, domain, serverip, gmail, gpass):
        self.sitekey = sitekey
        self.domain = domain.replace('https://', 'http://')
        self.serverip = serverip
        self.googleemail = gmail
        self.googlepass = gpass
        self.chrome = webdriver.Chrome()
        self.htmlcode = "<html><meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no'><head><script type='text/javascript' src='https://www.google.com/recaptcha/api.js'></script><script src='http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js' type='text/javascript'></script> <title>Captcha Harvester</title> <style type='text/css'> body{margin: 1em 5em 0 5em; font-family: sans-serif;}fieldset{display: inline; padding: 1em;}</style></head><body> <center> <h3>Captcha Token Harvester</h3> <h5>HTML by: @pxtvr</h5> <h5>Python by: @Cosm00_</h5> <form action='http://serveriphere:5000/solve' method='post'> <fieldset> <div class='g-recaptcha' data-sitekey='sitekeygoeshere' data-callback='sub'></div><p> <input type='submit' value='Submit' id='submit' style='color: #ffffff;background-color: #3c3c3c;border-color: #3c3c3c;display: inline-block;margin-bottom: 0;font-weight: normal;text-align: center;vertical-align: middle;-ms-touch-action: manipulation;touch-action: manipulation;cursor: pointer;background-image: none;border: 1px solid transparent;white-space: nowrap;padding: 8px 12px;font-size: 15px;line-height: 1.4;border-radius: 0;-webkit-user-select: none;-moz-user-select: none;-ms-user-select: none;user-select: none;'> </p></fieldset> </form> <fieldset> <h5 style='width: 10vh;'> <a style='text-decoration: none;' href='http://serveriphere:5000/json' target='_blank'>Usable Tokens</a> </h5> </fieldset> </center> <script>function sub(){document.getElementById('submit').click();}</script> </body></html>".replace('sitekeygoeshere',
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          self.sitekey).replace('serveriphere', self.serverip)
    def signin(self):
        self.chrome.get('https://accounts.google.com/signin/v2')
        while True:
            try:
                emailfield = self.chrome.find_element_by_xpath('//*[@type="email"]')
                break
            except:
                pass
        while True:
            try:
                emailfield.send_keys(self.googleemail)
                break
            except:
                pass
        while True:
            try:
                self.chrome.find_element_by_xpath('//*[text() = "Next"]').click()
                break
            except:
                pass
        while True:
            try:
                passfield = self.chrome.find_element_by_xpath('//*[@name="password"]')
                break
            except:
                pass
        while True:
            try:
                passfield.send_keys(self.googlepass)
                break
            except:
                pass
        while True:
            try:
                self.chrome.find_element_by_xpath('//*[@id="passwordNext"]').click()
                break
            except:
                pass
        while True:
            if 'My Account gives you quick access to settings and tools that let you safeguard your data' in self.chrome.page_source:
                break
            else:
                pass
        self.chrome.get('https://www.youtube.com/watch?v=ZAyvEft9MIs')
    def solve(self):
        self.chrome.get(self.domain)
        try:
            self.chrome.execute_script('document.write("{}")'.format(self.htmlcode))
        except selenium.common.exceptions.WebDriverException:
            pass
        while True:
            if 'Captcha Token Harvester' in self.chrome.page_source:
                break
            else:
                pass
        time.sleep(1)
        try:
            self.chrome.execute_script("var evt = document.createEvent('Event');evt.initEvent('load', false, false);window.dispatchEvent(evt);")
        except selenium.common.exceptions.WebDriverException:
            pass
        while True:
            if 'Success' in self.chrome.page_source:
                break
            else:
                pass



if __name__ == '__main__':
    sitekey = input('Enter Sitekey : ')
    domain = input('Solve For What Domain? : ')
    server = input('What is the IP of the token server? : ')
    gmail = input('Enter Gmail : ')
    gpass = getpass.getpass('Enter Gmail Password  : ')
    s = harvest(sitekey, domain, server, gmail, gpass)
    if gmail == '' or gpass == '':
        pass
    else:
        s.signin()
    input('Press Enter to Begin Solving')
    while True:
        s.solve()
