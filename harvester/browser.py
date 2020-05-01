import platform
import os
from uuid import uuid4
from enum import Enum
from typing import Tuple

__dir__ = os.path.dirname(os.path.abspath(__file__))
EXTENSION_PATH = os.path.join(
    os.path.dirname(__dir__), 'privacy-pass-extension')

browsers = {
    'chrome': 'Google Chrome',
    'brave': 'Brave Browser'
}


class BrowserEnum(Enum):
    CHROME = 'chrome'
    BRAVE = 'brave'


def launch(domain: str, server_address: Tuple[str, int], browser: BrowserEnum = BrowserEnum.CHROME, restart: bool = False):
    user_dir = ''
    browser = browser.value
    pac_script_url = f'http://{server_address[0]}:{server_address[1]}/{domain}.pac'
    app = browsers.get(browser)
    if not app:
        raise ValueError('no configuration for `{}` browser'.format(browser))

    system = platform.system()
    if system == 'Darwin':
        if not restart:
            user_dir = '--user-data-dir=/tmp/havester/' + str(uuid4())
        else:
            os.system(f'killall "{app}"')
        os.system(
            f"open -a '{app}' -n --args --proxy-pac-url='{pac_script_url}' --load-extension={EXTENSION_PATH} {user_dir} {domain}")
    elif system == 'Windows':
        if not restart:
            user_dir = '--user-data-dir=' + \
                os.path.join(os.environ['TEMP'], 'harvester', str(uuid4()))
        else:
            os.system(f'TASKKILL /IM {browser}.exe /F')
        os.system(
            f'start {browser} --proxy-pac-url="{pac_script_url}" --load-extension={EXTENSION_PATH} {user_dir} {domain}')
    else:
        raise RuntimeError(
            'automatic broswer functinality only avalible on MacOS and Windows for now')
