import platform
import os
from uuid import uuid4
from enum import Enum
from typing import Tuple, List

browsers = {
    'chrome': 'Google Chrome',
    'brave': 'Brave Browser'
}


class BrowserEnum(Enum):
    CHROME = 'chrome'
    BRAVE = 'brave'


def launch(domain: str, server_address: Tuple[str, int], browser: BrowserEnum = BrowserEnum.CHROME,
           restart: bool = False, width: int = 400, height: int = 580, browser_path: str = None, browser_args: List[str] = []):
    browser = browser.value
    pac_script_url = f'http://{server_address[0]}:{server_address[1]}/{domain}.pac'
    app = browsers.get(browser)
    if not app:
        raise ValueError('no configuration for `{}` browser'.format(browser))

    system = platform.system()
    browser_command = []

    if system == 'Darwin':
        browser_path = browser_path or f"open -a '{app}' -n --args"
        user_data_dir = f'--user-data-dir=/tmp/havester/{str(uuid4())}'
        restart_command = f'killall "{app}"'
    elif system == 'Windows':
        browser_path = browser_path or f"start {browser}"
        user_data_dir = f"--user-data-dir={os.path.join(os.environ['TEMP'], 'harvester', str(uuid4()))}"
        restart_command = f'TASKKILL /IM {browser}.exe /F'
    else:
        raise RuntimeError(
            'Automatic broswer functinality only avalible on MacOS and Windows for now')

    browser_command.append(browser_path)
    if restart:
        os.system(restart_command)
    else:
        browser_command.append(user_data_dir)

    browser_command.extend(browser_args)
    browser_command.extend((
        "--no-default-browser-check",
        f'--proxy-pac-url="{pac_script_url}"',
        f"--window-size={width},{height}",
        f'--app="http://{domain}"'
    ))

    print(browser_command)

    os.system(' '.join(browser_command))
