import harvester
from setuptools import setup, find_packages

with open('README.md') as f:
    long_description = f.read()

setup(
    name="captcha-harvester",
    version=harvester.__version__,
    author="Noah Cardoza",
    author_email="noahcardoza@gmail.com",
    description="Solve captchas yourself without having to pay for services like 2captcha for use in automated projects.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/NoahCardoza/CaptchaHarvester",
    include_package_data=True,
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'harvester = harvester.entry_point:entry_point'
        ]
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Environment :: MacOS X',
        'Environment :: Plugins',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Operating System :: MacOS',
        'Operating System :: MacOS :: MacOS 9',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Operating System :: Microsoft',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Microsoft :: Windows :: Windows 10',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        "Operating System :: OS Independent",
        'Topic :: Internet',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Browsers',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
        'Typing :: Typed',
    ],
    keywords=(
        'http, proxy, http proxy server, proxy server, http server,'
        'http web server, proxy framework, web framework, Python3,'
        'catpcha, recaptcha, hcaptcha, google, cloudflare, mitm,'
        'man in the middle, web server, web scraping, botting'
    )

)
