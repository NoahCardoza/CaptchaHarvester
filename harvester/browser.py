import platform
import os
from uuid import uuid4

browsers = {
    'chrome': 'Google Chrome',
    'brave': 'Brave Browser'
}


def launch(pac_script, browser='chrome', restart=False):
    user_dir = ''
    app = browsers.get(browser)
    if not app:
        raise ValueError('no configuration for `{}` browser'.format(browser))

    if platform.system() != 'Darwin':
        raise RuntimeError(
            'automatic broswer functinality only avalible on MacOS')

    if not restart:
        user_dir = '--user-data-dir=/tmp/havester/' + str(uuid4())
    os.system(
        "open -a '{}' -n --args --proxy-pac-url='{}' {}".format(app, pac_script, user_dir))
