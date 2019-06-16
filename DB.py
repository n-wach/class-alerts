import threading
import time
import uuid
from datetime import datetime

import bcrypt
from flask_sqlalchemy import SQLAlchemy

from Notifier import send_sms, send_email, send_activation_email, send_class_closed_email, send_class_open_email, \
    send_deactivation_email, send_password_change_email

db = SQLAlchemy()
db.session.expire_on_commit = False

ROLE_ADMIN = 0
ROLE_MARKETER = 1
ROLE_USER = 2


class User(db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(40), unique=True)
    role = db.Column(db.Integer)
    parent_user = db.Column(db.String(40))
    is_verified = db.Column(db.Boolean)
    verify_code = db.Column(db.String(40))
    is_paid = db.Column(db.Boolean)
    last_payment = db.Column(db.String(40))
    email = db.Column(db.String(100))
    phone = db.Column(db.Integer)
    available_sms = db.Column(db.Boolean)
    periodically_sms = db.Column(db.Boolean)
    unavailable_sms = db.Column(db.Boolean)
    available_call = db.Column(db.Boolean)
    periodically_call = db.Column(db.Boolean)
    bcrypt_password = db.Column(db.String(100))
    college = db.Column(db.String(30))
    registered_at = db.Column(db.DateTime)

    def __init__(self, parent, email, phone, raw_password, role=ROLE_USER):
        self.uuid = str(uuid.uuid4())
        self.role = role
        self.parent_user = parent
        self.is_verified = False
        self.verify_code = str(uuid.uuid4())
        self.is_paid = False
        self.last_payment = 0
        self.email = email
        self.phone = phone
        self.available_sms = True
        self.periodically_sms = True
        self.unavailable_sms = True
        self.available_call = False
        self.periodically_call = False
        self.set_password(raw_password, email=False)
        self.college = ""
        self.registered_at = datetime.now()

    def delete(self):
        for r in self.get_requests():
            r.delete()
        db.session.delete(self)
        db.session.commit()

    def set_password(self, raw_password, email=True):
        self.bcrypt_password = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
        db.session.commit()
        if email:
            send_password_change_email(self)

    def verify_password(self, raw_password):
        return bcrypt.checkpw(raw_password.encode(), self.bcrypt_password.encode())

    def send_sms(self, msg):
        try:
            send_sms(self.phone, msg)
        except:
            print("Exception on SMS to {}@{}".format(self, self.phone))

    def get_requests(self):
        return ClassRequest.query.filter_by(requester_uuid=self.uuid).all()

    def get_status(self):
        if self.role == ROLE_ADMIN:
            return "Admin"
        if self.role == ROLE_MARKETER:
            return "Marketer"
        if self.role == ROLE_USER:
            if not self.is_verified:
                return "Unverified User"
            if self.is_paid:
                return "Paid User"
            else:
                return "Unpaid User"

    def get_friendly_name(self):
        return "{}: {}".format(self.get_status(), self.email)

    def __str__(self):
        return "<{}>".format(self.get_friendly_name())


class PasswordResetRequest(db.Model):
    __tablename__ = "PasswordResetRequests"
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(40))
    user_uuid = db.Column(db.String(100))
    created_at = db.Column(db.DateTime)
    used_at = db.Column(db.DateTime)
    used = db.Column(db.Boolean)

    def __init__(self, user_uuid):
        self.uuid = str(uuid.uuid4())
        self.user_uuid = user_uuid
        self.created_at = datetime.now()
        self.used = False

    def attempt_use(self, new_password):
        if self.used:
            print("used")
            return False
        if (datetime.now() - self.created_at).total_seconds() > 600:
            print("expired")
            return False
        user = User.query.filter_by(uuid=self.user_uuid).first()
        if user:
            user.bcrypt_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            self.used_at = datetime.now()
            self.used = True
            db.session.commit()
            print("valid")
            return True
        print("no user")
        return False


class FreePaymentCode(db.Model):
    __tablename__ = "FreePaymentCodes"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(40))
    creator_uuid = db.Column(db.String(40))
    created_at = db.Column(db.DateTime)
    is_used = db.Column(db.Boolean)
    used_by_uuid = db.Column(db.String(40))
    used_on = db.Column(db.DateTime)

    def __init__(self, code, creator):
        self.code = code.lower()  # codes are capitalization independent
        self.creator_uuid = creator.uuid
        self.created_at = datetime.now()
        self.is_used = False

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def get_user(self):
        return User.query.filter_by(uuid=self.used_by_uuid).first()

    def get_creator(self):
        return User.query.filter_by(uuid=self.creator_uuid).first()

    def use(self, user):
        if self.is_used:
            return
        self.used_by_uuid = user.uuid
        user.is_paid = True
        self.is_used = True
        self.used_on = datetime.now()
        send_activation_email(user)
        db.session.commit()

    def __str__(self):
        return "<FreePaymentCode '{}'>".format(self.code)


class Payment(db.Model):
    __tablename__ = "Payments"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True)
    account_uuid = db.Column(db.String(40))
    is_complete = db.Column(db.Boolean)
    completed_at = db.Column(db.DateTime)
    started_at = db.Column(db.DateTime)
    purchaser_email = db.Column(db.String(100))  # assigned based on email of token using get_express_checkout_details

    def __init__(self, token, user):
        self.token = token
        self.account_uuid = user.uuid
        self.is_complete = False
        self.started_at = datetime.now()

    def process(self):
        if self.is_complete:
            return
        user = User.query.filter_by(uuid=self.account_uuid).first()
        user.is_paid = True
        send_activation_email(user)
        self.is_complete = True
        self.completed_at = datetime.now()

    def delete(self):
        if self.is_complete:
            return
        db.session.delete(self)
        db.session.commit()


class ClassRequest(db.Model):
    __tablename__ = "ClassRequests"
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(40))
    requester_uuid = db.Column(db.String(40))
    monitor_uuid = db.Column(db.String(40))
    notifications_sent = db.Column(db.Integer)
    last_notified = db.Column(db.DateTime)

    def __init__(self, requester, monitor):
        self.uuid = str(uuid.uuid4())
        self.requester_uuid = requester.uuid
        self.monitor_uuid = monitor.uuid
        self.notifications_sent = 0
        self.last_notified = datetime.now()

    def update(self):
        print("Updating", self)
        delay_notify = datetime.now() - self.last_notified
        monitor = self.get_monitor()
        if monitor.has_availability:
            if delay_notify.total_seconds() > (59 * (2 ** self.notifications_sent) - 5):
                user = self.get_requester()
                self.notifications_sent += 1
                self.last_notified = datetime.now()
                inst = monitor.class_instance
                subj = "OPEN: " + inst.display_name
                msg = "Status Update: {}\n" \
                      "View: {}\n" \
                      "Sign up: {}".format(inst.status_message, inst.info_url, inst.action_url)
                send_class_open_email(user, monitor)
                user.send_sms("{}\n{}".format(subj, msg))
        else:
            if self.notifications_sent > 0:
                user = self.get_requester()
                inst = monitor.class_instance
                subj = "CLOSED: " + inst.display_name
                msg = "Status Update: {}\n" \
                      "View: {}\n" \
                      "Sign up: {}".format(inst.status_message, inst.info_url, inst.action_url)
                send_class_open_email(user, monitor)
                user.send_sms("{}\n{}".format(subj, msg))
            self.notifications_sent = 0

    def get_monitor(self):
        return ClassMonitor.query.filter_by(uuid=self.monitor_uuid).first()

    def get_requester(self):
        return User.query.filter_by(uuid=self.requester_uuid).first()

    def delete(self):
        if len(ClassRequest.query.filter_by(monitor_uuid=self.monitor_uuid).all()) == 1:
            self.get_monitor().delete()  # delete the class if this is the only request for it
        db.session.delete(self)
        db.session.commit()

    def __str__(self):
        return "<Request by {} for {}>".format(self.get_requester(), self.get_monitor().class_instance)


class ClassMonitor(db.Model):
    __tablename__ = "ClassMonitors"
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(40))
    college = db.Column(db.String(30))
    class_instance = db.Column(db.PickleType)
    has_availability = db.Column(db.Boolean)
    last_checked = db.Column(db.DateTime)

    def __init__(self, college, class_instance):
        self.uuid = str(uuid.uuid4())
        self.college = college
        self.class_instance = class_instance
        self.has_availability = False
        self.last_checked = datetime.now()

    @staticmethod
    def update_with_context(mon, app):
        with app.app_context():
            mon.update()

    def update(self):
        # print("Updating", self)
        cl = self.class_instance
        self.has_availability = cl.update_status()
        self.class_instance = cl
        self.last_checked = datetime.now()
        db.session.add(self)
        for request in ClassRequest.query.filter_by(monitor_uuid=self.uuid).all():
            request.update()
            db.session.add(request)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __str__(self):
        return "<Monitor {}>".format(str(self.class_instance))


def update_all(app):
    try:
        start = time.time()
        class_monitors = ClassMonitor.query.all()

        threads = (threading.Thread(target=ClassMonitor.update_with_context, args=(monitor, app)) for monitor in
                   class_monitors)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        # print("Updated {} listings in {} seconds".format(len(class_monitors), time.time() - start))
    except Exception as e:
        print(str(e))


def attempt_get_user(email, password):
    user = User.query.filter_by(email=email).first()
    if user is None:
        return None
    if user.verify_password(password):
        return user


def get_user(u):
    return User.query.filter_by(uuid=u).first()
