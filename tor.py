import time
import os

import requests
from stem import Signal
from stem.control import Controller
import logging

logger = logging.getLogger("app.tor")

use_tor = os.environ.get("USE_TOR") == "True"
tor_password = os.environ.get("TOR_PASSWORD", "password")
last_refresh = time.time()

headers = {'User-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"}


def urlpost(url, tor=False, **kwargs):
    params = kwargs
    if "headers" not in params.keys():
        params["headers"] = headers

    if use_tor and tor:
        return tor_urlpost(url, **params)
    else:
        return std_urlpost(url, **params)


def std_urlpost(url, **kwargs):
    logger.debug("Getting without TOR: {}".format(url))
    return requests.post(url, **kwargs)


def tor_urlpost(url, **kwargs):
    logger.debug("Getting with TOR: {}".format(url))
    c_refresh_ip()

    session = requests.session()
    session.proxies = {
        "http": "socks5h://localhost:9050",
        "https": "socks5h://localhost:9050"}
    return session.post(url, **kwargs)


def urlget(url, tor=False, **kwargs):
    params = kwargs
    if "headers" not in params.keys():
        params["headers"] = headers

    if use_tor and tor:
        return tor_urlget(url, **params)
    else:
        return std_urlget(url, **params)


def std_urlget(url, **kwargs):
    logger.debug("Getting without TOR: {}".format(url))
    return requests.get(url, **kwargs)


def tor_urlget(url, **kwargs):

    logger.debug("Getting with TOR: {}".format(url))
    c_refresh_ip()

    session = requests.session()
    session.proxies = {
        "http": "socks5h://localhost:9050",
        "https": "socks5h://localhost:9050"}
    return session.get(url, **kwargs)


def c_refresh_ip():
    global last_refresh
    if time.time() - last_refresh > 4:
        last_refresh = time.time()
        refresh_ip()


def refresh_ip():
    logger.debug("Refreshing TOR IP")
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password=tor_password)
        controller.signal(Signal.NEWNYM)
