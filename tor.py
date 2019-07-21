import time
import os

import requests
from stem import Signal
from stem.control import Controller
import logging
logger = logging.getLogger("app.tor")

use_tor = os.environ.get("USE_TOR", False)
last_refresh = time.time()

headers = {'User-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"}


def urlopen(url):
    if use_tor:
        return tor_urlopen(url)
    else:
        return std_urlopen(url)


def std_urlopen(url):
    logger.debug("Fetching without TOR: {}".format(url))
    return requests.get(url, headers=headers)


def tor_urlopen(url):
    logger.debug("Fetching with TOR: {}".format(url))
    if time.time() - last_refresh > 4:
        refresh_ip()

    session = requests.session()
    session.proxies = {
        "http": "socks5h://localhost:9050",
        "https": "socks5h://localhost:9050"}
    return session.get(url, headers=headers)


def refresh_ip():
    logger.info("Refreshing TOR IP")
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password='password')
        controller.signal(Signal.NEWNYM)
