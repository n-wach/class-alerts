import os
import random
import re
import uuid
from datetime import datetime
from time import time, sleep

from babel.dates import format_timedelta, format_datetime
from flask import Flask, session, render_template, url_for, abort, redirect, request
from flask_apscheduler import APScheduler
from twilio.twiml.voice_response import VoiceResponse

from colleges import colleges, college_names, get_user_college, college_short_names
from decorators import requires_signin, requires_paid, requires_verified, requires_form_field, displays_error, \
    requires_role, errors
from Notifier import send_verification_email, prepare_templates, send_password_reset_email, send_contact_email
from DB import db, User, update_all, attempt_get_user, get_user, ROLE_ADMIN, ClassRequest, ROLE_MARKETER, \
    FreePaymentCode, PasswordResetRequest

print("Setting up...")
app = Flask(__name__,
            static_url_path='',
            static_folder='static')

print("Configuring...")
DEV_GEN = True
app.secret_key = os.environ.get("SECRET_KEY")


print("Defining Constants...")
PATTERN_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
PATTERN_MASS_MESSAGE = re.compile(r".{20,}")
PATTERN_CODE = re.compile(r"[A-z0-9]{5,}")
PATTERN_TARGET_ROLE = re.compile(r"[14]")
PATTERN_NOT_EMPTY = re.compile(r"\S+")
PATTERN_PASSWORD = re.compile(r".{6,}")
PATTERN_EMAIL = re.compile(r"[0-9]{0,11}")
PATTERN_PHONE = re.compile(r"1[0-9]{10}")
PATTERN_CRN = re.compile(r"[0-9]{5}")
PATTERN_TERM = re.compile(r"[0-9]{6}")

MAX_USER_REQUESTS = 15


@app.route("/")
def landing_page():
    if "uuid" not in session:
        return render_template("public/about.html")

    user = get_user(session["uuid"])
    if user is None:
        del session["uuid"]
        return render_template("public/about.html")
    elif not user.is_verified:
        return redirect(url_for("verify"))
    elif user.college not in college_short_names:
        return redirect(url_for("college_select"))
    return render_template("user/home.html")


@app.route("/select", methods=["POST"])
@requires_signin
@requires_form_field("college", if_missing="College missing", redirect_url_for="landing_page",
                     value_pattern=PATTERN_NOT_EMPTY)
def do_college_select():
    user = get_user(session["uuid"])
    college = request.form.get("college")
    ret = request.form.get("ret", url_for("landing_page"))
    if college in college_short_names:
        user.college = college
        db.session.commit()
        for req in user.get_requests():
            if req.college != college:
                req.delete()
        return redirect(ret)
    else:
        abort(400, "College not found")


@app.route("/select")
@requires_signin
def college_select():
    user = get_user(session["uuid"])
    if user.college not in college_names:
        return render_template("user/college-selection.html")
    else:
        return redirect(url_for("settings"))


@app.route("/signin", methods=["POST"])
@requires_form_field("email", if_missing="Email missing", redirect_url_for="login",
                     value_pattern=PATTERN_NOT_EMPTY)
@requires_form_field("password", if_missing="Password missing", redirect_url_for="login",
                     value_pattern=PATTERN_NOT_EMPTY)
def do_signin():
    login_pw = request.form.get("password")
    login_email = request.form.get("email")
    user = attempt_get_user(login_email, login_pw)
    if user is None:
        return errors("Invalid Email or Password", "signin")
    else:
        session["uuid"] = user.uuid
        print("{} logged in".format(user))
        return redirect(url_for("landing_page"))


@app.route("/signin")
@displays_error
def signin(error):
    if "uuid" in session:
        return redirect(url_for("landing_page"))
    return render_template("public/sign-in.html", error=error)


@app.route("/signup", methods=["POST"])
@requires_form_field("email", if_missing="Email missing", redirect_url_for="signup", value_pattern=PATTERN_NOT_EMPTY)
@requires_form_field("password", if_missing="Password missing", redirect_url_for="signup",
                     value_pattern=PATTERN_NOT_EMPTY)
@requires_form_field("confirm", if_missing="Password confirmation missing", redirect_url_for="signup",
                     value_pattern=PATTERN_NOT_EMPTY)
def do_signup():
    create_email = request.form.get("email")
    create_pw = request.form.get("password")
    confirm_pw = request.form.get("confirm")
    create_phone = request.form.get("phone")
    match = User.query.filter_by(email=create_email).first()

    if match is not None:
        return errors("Email already in use", "signup")
    elif len(create_pw) < 6:
        return errors("Password must be at least 6 characters long", "signup")
    elif create_pw != confirm_pw:
        return errors("Passwords do not match", "signup")
    elif create_phone != "" and (len(create_phone) != 11 or not PATTERN_PHONE.match(create_phone)):
        return errors("Invalid Phone Format", "signup")

    user = User("root", create_email, create_phone, create_pw)

    session["uuid"] = user.uuid

    if len(User.query.all()) == 0:
        user.role = ROLE_ADMIN
        user.is_verified = True
        user.is_paid = True
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("landing_page"))
    else:
        send_verification_email(user)
        db.session.add(user)
        db.session.commit()
        session["uuid"] = user.uuid
        return redirect(url_for("verify"))


@app.route("/signup", methods=["GET"])
@displays_error
def signup(error):
    if "uuid" in session:
        return redirect(url_for("landing_page"))
    return render_template("public/sign-up.html", error=error)


@app.route("/verify/<code>")
@requires_signin
@requires_verified(False)
def do_verify(code):
    if not PATTERN_UUID.match(code):
        return "Verification code missing or invalid"
    user = get_user(session["uuid"])
    if code == user.verify_code:
        user.is_verified = True
        db.session.commit()
    return redirect(url_for("landing_page"))


@app.route("/verify", methods=["GET"])
@requires_signin
@requires_verified(False)
@displays_error
def verify(error):
    return render_template("user/verify.html", error=error)


@app.route("/message", methods=["POST"])
@requires_role(ROLE_ADMIN)
@requires_form_field("message", if_missing="Missing message", redirect_url_for="message",
                     value_pattern=PATTERN_MASS_MESSAGE, if_invalid="Message too short!")
def do_message():
    for user in User.query.all():
        user.message("Important Message!", request.form.get("message"), request.form.get("message"))
    return "Sent message via email and SMS: '%s'" % request.form.get("message")


@app.route("/message", methods=["GET"])
@requires_role(ROLE_ADMIN)
@displays_error
def message(error):
    return render_template("admin/mass-message.html", error=error)


@app.route("/codes", methods=["GET"])
@requires_role(ROLE_MARKETER)
@displays_error
def view_codes(error):
    return render_template("admin/view-codes.html", error=error)


@app.route("/generate_code", methods=["POST"])
@requires_role(ROLE_MARKETER)
@requires_form_field("code", if_missing="Missing code", redirect_url_for="view_codes",
                     value_pattern=PATTERN_CODE, if_invalid="Codes must be at least 5 characters (letters and numbers only)")
def do_generate_free_code():
    code = request.form.get("code").lower()
    if len(FreePaymentCode.query.filter_by(code=code).all()) > 0:
        return errors("Code has already been generated.", "view_codes")
    else:
        user = get_user(session["uuid"])
        p = FreePaymentCode(code, user)
        print("{} generated code {}".format(user, p))
        db.session.add(p)
        db.session.commit()
        return redirect(url_for("view_codes"))


@app.route("/use_code", methods=["POST"])
@requires_paid(paid=False)
@requires_form_field("code", if_missing="Missing code", redirect_url_for="view_codes",
                     value_pattern=PATTERN_CODE, if_invalid="Codes must be at least 5 characters (letters and numbers only)")
def do_use_free_code():
    code = request.form.get("code").lower()
    fpc = FreePaymentCode.query.filter_by(code=code).first()
    if fpc is None:
        return errors("Code does not exist", "renew")
    elif fpc.is_used:
        return errors("Code has already been used", "renew")
    else:
        user = get_user(session["uuid"])
        fpc.use(user)
        return redirect(url_for("landing_page"))


@app.route("/delete_code", methods=["POST"])
@requires_role(ROLE_MARKETER)
@requires_form_field("delete-code", if_missing="Missing code", redirect_url_for="view_codes",
                     value_pattern=PATTERN_CODE, if_invalid="Codes must be at least 5 characters (letters and numbers only)")
def do_delete_code():
    code = request.form.get("delete-code").lower()
    if len(FreePaymentCode.query.filter_by(code=code).all()) == 0:
        return errors("Code does not exist.", "view_codes")
    else:
        frc = FreePaymentCode.query.filter_by(code=code).first()
        if frc.is_used:
            return errors("Code has already been used, and cannot be deleted.", "view_codes")
        frc.delete()
        db.session.commit()
        return redirect(url_for("view_codes"))


@app.route("/set_paid", methods=["POST"])
@requires_role(ROLE_MARKETER)
def set_paid():
    target = get_user(request.form.get("target-uuid"))
    is_paid = request.form.get("is-paid") == "true"
    user = get_user(session["uuid"])
    if user.role < target.role:
        target.is_paid = is_paid
        db.session.commit()
        return redirect(url_for("view_all"))
    else:
        return abort(403, "Insufficient Role")


@app.route("/remove_class", methods=["POST"])
@requires_signin
def remove_class():
    try:
        monitor_uuid = request.form.get("uuid")
        user = get_user(session["uuid"])
        req = ClassRequest.query.filter_by(requester_uuid=user.uuid, monitor_uuid=monitor_uuid).first()
        print("{} removed {}".format(user, req))
        req.delete()
    except Exception as e:
        print(e)
        abort(400, "Class info is invalid")
    return redirect(url_for("landing_page"))


@app.route("/add", methods=["GET"])
@requires_signin
@requires_paid(True)
@displays_error
def add(error):
    return render_template("user/add.html", error=error)


@app.route("/add", methods=["POST"])
@requires_signin
@requires_paid(True)
def do_add():
    try:
        user = get_user(session["uuid"])
        college = get_user_college(user)

        verified = college.verify_add_request(request)
        if verified is not True:
            return verified  # returns error otherwise

        class_monitor = college.monitor_from_add_request(request)

        if len(ClassRequest.query.filter_by(monitor_uuid=class_monitor.uuid, requester_uuid=user.uuid).all()) > 0:
            return errors("You've already added this class!", "add")
        elif len(user.get_requests()) >= MAX_USER_REQUESTS:
            return errors("You can't request more than " + str(MAX_USER_REQUESTS) + " classes at a time...", "add")
        else:
            req = ClassRequest(user, class_monitor)
            db.session.add(req)
            db.session.commit()
            print("{} added {}".format(user, req))
            return redirect(url_for("landing_page"))
    except Exception as e:
        print(str(e))
        msg = "Something went wrong.  Make sure everything is correct, then contact support."
        return errors(msg, "add")


@app.route("/forgot", methods=["POST"])
@requires_form_field("email", if_missing="Email missing", redirect_url_for="forgot_page", value_pattern=PATTERN_EMAIL)
def forgot():
    email = request.form.get("email")
    user = User.query.filter_by(email=email).first()
    if user:
        prr = PasswordResetRequest(user.uuid)
        db.session.add(prr)
        db.session.commit()
        send_password_reset_email(user, prr)
    else:
        sleep(1)
    return render_template("public/forgot-response.html", forgot_email=email)


@app.route("/forgot")
@displays_error
def forgot_page(error):
    return render_template("public/forgot.html", error=error)


@app.route("/password_reset/<reset_uuid>")
@displays_error
def reset_password_page(error, reset_uuid):
    return render_template("public/set-password.html", reset_uuid=reset_uuid, error=error)


@app.route("/password_reset/<reset_uuid>", methods=["POST"])
def reset_password(reset_uuid):
    prr = PasswordResetRequest.query.filter_by(uuid=reset_uuid).first()
    password = request.form.get("password", "")
    c_password = request.form.get("c_password", "")
    if len(password) < 6:
        return errors("Password must be at least 6 characters", "reset_password_page", reset_uuid=reset_uuid)
    if password != c_password:
        return errors("Passwords do not match", "reset_password_page", reset_uuid=reset_uuid)
    print(prr)
    if prr:
        if prr.attempt_use(password):
            return errors("Password reset", "signin")
    return errors("Invalid or Expired Reset Code", "reset_password_page", reset_uuid=reset_uuid)


@app.route("/delete_uuid", methods=["POST", "GET"])
@requires_signin
def delete_uuid():
    cur_user = get_user(session["uuid"])
    d = None
    if request.form.get("delete-uuid") is not None:
        d = request.form.get("delete-uuid")
    elif session.get("delete-uuid") is not None:
        d = session["delete-uuid"]
        session["delete-uuid"] = None
    else:
        abort(400, "No account specified")

    if get_user(d) is None:
        abort(400, "Invalid UUID")

    print("{} attempting to delete {}".format(cur_user, get_user(d)))

    if d == cur_user.uuid:
        session.clear()
        cur_user.delete()
        return redirect(url_for("landing_page"))
    if cur_user.role < get_user(d).role:
        get_user(d).delete()
        return redirect(url_for("view_all"))
    else:
        abort(401, "Insufficient Role")


@app.route("/settings/<prop>", methods=["GET"])
@requires_signin
@displays_error
def settings(error, prop):
    if prop == "password":
        return render_template("user/settings/password.html", error=error)
    elif prop == "notification":
        return render_template("user/settings/notification.html", error=error)
    elif prop == "college":
        return render_template("user/settings/college.html", error=error)
    elif prop == "delete":
        return render_template("user/settings/delete.html", error=error)
    else:
        return render_template("user/settings/settings.html", error=error)


@app.route("/settings", methods=["GET"])
@requires_signin
@displays_error
def settings_list(error):
    return render_template("user/settings/settings.html", error=error)


@app.route("/settings/<prop>", methods=["POST"])
@requires_signin
def update_settings(prop):
    user = get_user(session.get("uuid"))
    if prop == "password":
        old_password = request.form.get("o_pw")
        new_password_1 = request.form.get("n_pw_1")
        new_password_2 = request.form.get("n_pw_2")
        if user.verify_password(old_password):
            if new_password_1 != new_password_2:
                return errors("New passwords do not match", "settings", prop="password")
            elif not PATTERN_PASSWORD.match(new_password_1):
                return errors("Password must be at least 6 characters long", "settings", prop="password")
            else:
                user.set_password(new_password_1)
                db.session.commit()
                return redirect(url_for("settings", prop="password"))
        else:
            return errors("Invalid old password", "settings", prop="password")
    elif prop == "notification":
        phone = request.form.get("phone")
        a_sms = request.form.get("a_sms", False)
        p_sms = request.form.get("p_sms", False)
        u_sms = request.form.get("u_sms", False)
        a_call = request.form.get("a_call", False)
        p_call = request.form.get("p_call", False)
        if PATTERN_PHONE.match(phone) or phone == "":
            if user.phone != phone:
                user.phone = phone
                print("User {} changed phone number to '{}'".format(user, str(phone)))
            if user.phone == "":
                user.available_call = False
                user.periodically_call = False
                user.available_sms = False
                user.periodically_sms = False
                user.unavailable_sms = False
            else:
                user.available_call = a_call
                user.periodically_call = p_call
                user.available_sms = a_sms
                user.periodically_sms = p_sms
                user.unavailable_sms = u_sms
            db.session.commit()
            return redirect(url_for("settings", prop="notification"))
        else:
            return errors("Invalid phone", "settings", prop="notification")
    elif prop == "delete":
        session["delete-uuid"] = session["uuid"]
        return redirect(url_for("delete_uuid"))
    else:
        return errors("Nothing to update", "settings_list")


@app.route("/view_all", methods=["GET"])
@requires_role(ROLE_ADMIN)
def view_all():
    return render_template("admin/view-accounts.html")


@app.route("/renew", methods=["GET"])
@requires_paid(False)
@displays_error
def renew(error):
    return render_template("user/renew.html", error=error)


@app.route("/signout")
def signout():
    session.clear()
    return redirect(url_for("landing_page"))


@app.route("/contact", methods=["POST"])
@requires_form_field("email", if_missing="Email missing", redirect_url_for="contact_page", value_pattern=PATTERN_EMAIL)
@requires_form_field("message", if_missing="Message missing", redirect_url_for="contact_page", value_pattern=PATTERN_NOT_EMPTY)
def contact():
    email = request.form.get("email")
    subject = request.form.get("subject")
    if not subject:
        subject = "No Subject"
    msg = request.form.get("message")
    send_contact_email(email, subject, msg)
    return errors("Your message has been sent", "contact_page")


@app.route("/contact")
@displays_error
def contact_page(error):
    return render_template("public/contact.html", error=error)


@app.route("/request")
@displays_error
def college_request_page(error):
    return render_template("public/contact.html", error=error, college_request=True)


@app.route("/privacy")
def privacy_page():
    return render_template("public/privacy.html")


@app.route("/terms")
def terms_page():
    return render_template("public/terms.html")


@app.route("/about")
def about_page():
    return render_template("public/about.html")


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

print("Adding Voice endpoints")
@app.route("/voice/open", methods=["GET", "POST"])
def voice_open():
    resp = VoiceResponse()
    resp.say("A class you're monitoring on Class Alerts has an available spot.", loop=5)
    resp.hangup()
    return str(resp)


print("Loading Notifier templates")
prepare_templates(app)


print("Preparing PayPal service handlers")

import Payments
Payments.route(app)


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
