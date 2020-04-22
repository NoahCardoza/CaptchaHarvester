import platform
import os
from uuid import uuid4

browsers = {
    'chrome': 'Google Chrome',
    'brave': 'Brave Browser'
}


def launch(domain, pac_script, browser='chrome', restart=False):
    user_dir = ''
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
            f"open -a '{app}' -n --args --proxy-pac-url='{pac_script}' {user_dir} {domain}")
    elif system == 'Windows':
        if not restart:
            user_dir = '--user-data-dir=' + \
                os.path.join(os.environ['TEMP'], 'harvester', str(uuid4()))
        else:
            os.system(f'TASKKILL /IM {browser}.exe /F')
        os.system(
            f'start {browser} --proxy-pac-url="{pac_script}" {user_dir} {domain}')
    else:
        raise RuntimeError(
            'automatic broswer functinality only avalible on MacOS and Windows for now')
