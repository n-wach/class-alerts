import os
import random
import uuid
from datetime import datetime
from time import time

from babel.dates import format_timedelta, format_datetime
from flask import Flask, session, abort, request
from flask_apscheduler import APScheduler

from db import db, User, update_all, FreePaymentCode
from notifier import prepare_templates
from colleges import colleges, get_user_college

print("Setting up...")
app = Flask(__name__,
            static_url_path='',
            static_folder='static')


print("Configuring...")
app.secret_key = os.environ.get("SECRET_KEY")


print("Defining Constants...")
MAX_USER_REQUESTS = 15
DEV_GEN = True


print("Routing pages...")
import pages
pages.route(app)


print("Routing api")
import api
api.route(app)


print("Adding Voice endpoints")
import voice
voice.route(app)


print("Preparing PayPal service handlers")
import payments
payments.route(app)


print("Loading Notifier templates")
prepare_templates(app)


print("Adding CSRF Request Handlers")


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get('csrf_token', None)
        sent = request.form.get('csrf_token')
        if not token or token != sent:
            abort(403,
                  "Invalid CSRF Token: {} should have been {}.  Try refreshing the previous page.".format(sent, token))


@app.after_request
def csrf_pop(response):
    if request.method == "POST":
        if 200 <= response.status_code < 400:
            session.pop('csrf_token', None)
    return response


print("Defining Jinja Globals...")
with app.app_context():
    def get_new_csrf_token():
        token = str(uuid.uuid4())
        session["csrf_token"] = token
        return token

    def get_all_users():
        return User.query.all()

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
                                 get_all_users=get_all_users,
                                 get_all_codes=get_all_codes,
                                 get_new_csrf_token=get_new_csrf_token,
                                 current_user=current_user,
                                 colleges=colleges,
                                 get_user_college=get_user_college,
                                 time=time)


print("Creating Database Manager")
if not os.getcwd().endswith("Alerts"):
    raise EnvironmentError("Working directory must be /Alerts.  Alerts.db is expected in the working directory")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.getcwd() + '/Alerts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)


print("Creating Scheduler...")


def background_monitor():
    with app.app_context():
        update_all(app)


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

if DEV_GEN:
    with app.app_context():
        print("Generating DB")
        db.create_all()
        print("Done!")

print("Starting...")
