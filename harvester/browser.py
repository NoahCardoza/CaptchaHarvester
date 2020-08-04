import platform
import os
from uuid import uuid4
from enum import Enum
from typing import Tuple, List, Union
import tempfile
import logging
import subprocess
from threading import Thread
from functools import partial

log = logging.getLogger('harvester')
browsers = {
    'chrome': 'Google Chrome',
    'brave': 'Brave Browser'
}

restart_commands = {
    'Darwin': 'killall "{app}"',
    'Windows': 'TASKKILL /IM {browser}.exe /F'
}


class BrowserEnum(Enum):
    CHROME = 'chrome'
    BRAVE = 'brave'


def read_osx_defults(plist: str, binary: str) -> str:
    """
    Looks for the preferences files that indicate from which location
    the specified browser was launched last.
    """
    import plistlib
    plist_file = f'{os.environ["HOME"]}/Library/Preferences/{plist}.plist'
    if os.path.exists(plist_file):
        binary_path = plistlib.readPlist(
            plist_file).get('LastRunAppBundlePath')
        if binary_path:
            return os.path.join(binary_path, 'Contents', 'MacOS', binary)


def read_windows_registry(browser: str) -> str:
    """
    Reads the Windows registry to find the paths to the specified browser.
    """
    import winreg as reg
    reg_path = f'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{browser}.exe'
    exe_path = None
    for install_type in reg.HKEY_CURRENT_USER, reg.HKEY_LOCAL_MACHINE:
        try:
            reg_key = reg.OpenKey(install_type, reg_path, 0, reg.KEY_READ)
            exe_path = reg.QueryValue(reg_key, None)
            reg_key.Close()
            if not os.path.isfile(exe_path):
                continue
        except WindowsError:
            pass
        else:
            break
    return exe_path


registry = {
    'Darwin': {
        'chrome': partial(read_osx_defults, 'com.google.Chrome', 'Google Chrome'),
        'brave': partial(read_osx_defults, 'com.brave.Browser', 'Brave Browser')
    },
    'Windows': {
        'chrome': partial(read_windows_registry, 'chrome'),
        'brave': partial(read_windows_registry, 'brave')
    }
}


def get_browser_binary_location(browser: str) -> str:
    """
    Generalized function to find the default installs of popular browsers
    regardless of running OS 
    """
    try:
        return registry.get(platform.system())[browser]()
    except KeyError:
        return None


def launch(domain: str, server_address: Tuple[str, int], browser: Union[BrowserEnum, str] = BrowserEnum.CHROME,
           restart: bool = False, width: int = 400, height: int = 580, browser_path: str = None, browser_args: List[str] = [],
           extensions: str = None, verbose: bool = False):

    if browser is not BrowserEnum:
        try:
            browser = BrowserEnum(browser)
            execute_path = False
        except ValueError:
            execute_path = True

    if not execute_path:
        browser = browser.value

    system = platform.system()
    browser_command = []

    if not execute_path:
        binary_location = get_browser_binary_location(browser)
        if binary_location:
            browser_command.append(binary_location)
        else:
            raise RuntimeError(
                'Automatic broswer functinality only avalible on MacOS and Windows for now.\n'
                'If you are running one of the above OS\'s then the harvester wasn\'t able to '
                'find the browser in it\'s default location.\n'
                'Try passing the full path to a browser executeable or the command you\'d use '
                'to launch it instead.')
    else:
        browser_command.append(browser)

    temp_dir = tempfile.TemporaryDirectory()
    user_data_dir = f'--user-data-dir={os.path.join(temp_dir.name, "Profiles")}'

    if restart:
        if not execute_path:
            try:
                os.system(restart_commands[system].format(
                    browser=browser,
                    app=browsers[browser]
                ))
            except KeyError:
                raise RuntimeError('Can not automatically restart your browser on your system.\n'
                                   '(Psst! Open an issue if you\'d like to see this functionality in the future.'
                                   )
        raise RuntimeError(
            'Cannot restart browser when passing path as browser parameter.')
    else:
        browser_command.append(user_data_dir)

    if extensions:
        browser_command.append(f'--load-extension={extensions}')

    browser_command.extend(browser_args)
    browser_command.extend((
        '--ignore-certificate-errors',
        '--ignore-urlfetcher-cert-requests',
        '--no-default-browser-check',
        '--no-check-default-browser',
        '--no-first-run',
        f'--host-rules=MAP {domain} {server_address[0]}:{server_address[1]}',
        f"--window-size={width},{height}",
        f'--app=https://{domain}'
    ))

    thread = Thread(target=subprocess.run, args=(
        browser_command,), kwargs={'capture_output': not verbose}, daemon=True)
    thread.start()
    return thread
