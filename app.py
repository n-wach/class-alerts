import os
import random
import uuid
from datetime import datetime
from time import time

from babel.dates import format_timedelta, format_datetime
from flask import Flask, session, abort, request
from flask_apscheduler import APScheduler

import logging.handlers

from werkzeug.contrib.fixers import ProxyFix

logger = logging.getLogger("app")
level_str = os.environ.get("LOG_LEVEL")
levels = {
    "info": logging.INFO,
    "debug": logging.DEBUG
}
logger.setLevel(levels.get(level_str, logging.INFO))

formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

file_logger = logging.handlers.TimedRotatingFileHandler("logs/Alerts.log", when="midnight")
file_logger.setFormatter(formatter)
file_logger.setLevel(logging.DEBUG)
logger.addHandler(file_logger)

console_logger = logging.StreamHandler()
console_logger.setFormatter(formatter)
console_logger.setLevel(logging.DEBUG)
logger.addHandler(console_logger)

logger.info("Running app...")


logger.info("Preparing colleges")
from db import db, User, update_all, FreePaymentCode
from notifier import prepare_templates
from colleges import colleges

logger.info("Setting up...")
app = Flask(__name__,
            static_url_path='',
            static_folder='static')


logger.info("Configuring...")
app.secret_key = os.environ.get("SECRET_KEY")
server_name = os.environ.get("SERVER_NAME")
if server_name is not None:
    logger.info("Server name is {}".format(server_name))
    app.config["SERVER_NAME"] = server_name
    # if we have server name, we likely have https
    app.config["PREFERRED_URL_SCHEME"] = "https"


logger.info("Defining Constants...")
MAX_USER_REQUESTS = 15


logger.info("Routing pages...")
import pages
pages.route(app)


logger.info("Routing api")
import api
api.route(app)


logger.info("Adding Voice endpoints")
import voice
voice.route(app)


logger.info("Preparing PayPal service handlers")
import payments
payments.route(app)


logger.info("Preparing Google OAuth")
import oauth
oauth.setup(app)


logger.info("Adding CSRF Request Handlers")


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get('csrf_token', None)
        sent = request.form.get('csrf_token')
        if not token or token != sent:
            logger.debug("Invalid CSRF Token: {} should have been {}".format(sent, token))
            abort(403, "Invalid CSRF Token.  Try refreshing the previous page.")


@app.after_request
def csrf_pop(response):
    if request.method == "POST":
        if 200 <= response.status_code < 400:
            session.pop('csrf_token', None)
            logger.debug("Consuming CSRF token")
    return response


logger.info("Defining Jinja Globals...")
with app.app_context():
    def get_new_csrf_token():
        token = str(uuid.uuid4())
        session["csrf_token"] = token
        logger.debug("Generating new CSRF token")
        return token


    def get_all_codes():
        return FreePaymentCode.query.all()

    def current_user():
        if "uuid" in session:
            return User.query.filter_by(uuid=session["uuid"]).first()
        return None

    def get_random_color():
        colors = ["red", "pink", "purple", "deep-purple", "indigo", "blue", "light-blue", "cyan", "teal", "green",
                  "light-green", "amber", "orange", "deep-orange"]
        return "mdl-color--" + random.choice(colors)

    def time_delta(value):
        dt = value - datetime.now()
        return format_timedelta(dt, add_direction=True, locale='en_US')

    def format_date(value):
        return format_datetime(value, locale="en_US")

    app.jinja_env.filters["timedelta"] = time_delta
    app.jinja_env.filters["date"] = format_date
    app.jinja_env.globals.update(get_random_color=get_random_color,
                                 get_new_csrf_token=get_new_csrf_token,
                                 current_user=current_user,
                                 colleges=colleges,
                                 time=time)


logger.info("Loading Notifier templates")
prepare_templates(app)


logger.info("Creating Database Manager")
if not os.getcwd().endswith("Alerts"):
    raise EnvironmentError("Working directory must be /Alerts.  Alerts.db is expected in the working directory")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.getcwd() + '/Alerts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
if not os.path.exists(os.getcwd() + '/Alerts.db'):
    logger.critical("Creating Database")
    with app.app_context():
        db.create_all()


logger.info("Creating Scheduler...")


def background_monitor():
    with app.app_context():
        update_all(app)


background_monitor()

app.config["SCHEDULER_API_ENABLED"] = False
app.config["JOBS"] = [
    {
        'id': 'monitor',
        'func': __name__ + ':background_monitor',
        'trigger': 'interval',
        'seconds': 5,
        'max_instances': 10
    }
]
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

logger.info("Starting...")
