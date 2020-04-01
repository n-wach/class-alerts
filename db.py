import threading
import time
import uuid
from datetime import datetime

import bcrypt
from flask_sqlalchemy import SQLAlchemy

from notifier import send_activation_email, send_password_change_email, \
    send_class_closed_email, send_class_open_email, send_class_remind_email,\
    send_call_open, send_call_remind, \
    send_sms_open, send_sms_remind, send_sms_close

import logging

logger = logging.getLogger("app.db")

db = SQLAlchemy()
db.session.expire_on_commit = False

ROLE_ADMIN = 10
ROLE_MARKETER = 100
ROLE_USER = 200

update_count = 0


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

    def __init__(self, parent, email, raw_password, role=ROLE_USER):
        self.uuid = str(uuid.uuid4())
        self.role = role
        self.parent_user = parent
        self.is_verified = False
        self.verify_code = str(uuid.uuid4())
        self.is_paid = False
        self.last_payment = 0
        self.email = email
        self.phone = ""
        self.available_sms = True
        self.periodically_sms = True
        self.unavailable_sms = True
        self.available_call = False
        self.periodically_call = False
        self.set_password(raw_password, email=False)
        self.college = ""
        self.registered_at = datetime.now()
        logger.debug("Created {}".format(self))

    def delete(self):
        for r in self.get_requests():
            r.delete()
        logger.debug("Deleted {}".format(self))
        db.session.delete(self)
        db.session.commit()

    def set_password(self, raw_password, email=True):
        self.bcrypt_password = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
        db.session.commit()
        if email:
            send_password_change_email(self)

    def verify_password(self, raw_password):
        return bcrypt.checkpw(raw_password.encode(), self.bcrypt_password.encode())

    def attempt_notify(self, ntype, monitor):
        if ntype == "open":
            send_class_open_email(self, monitor)
            if self.available_call:
                send_call_open(self, monitor)
            if self.available_sms:
                send_sms_open(self, monitor)
        elif ntype == "remind":
            send_class_remind_email(self, monitor)
            if self.periodically_call:
                send_call_remind(self, monitor)
            if self.periodically_sms:
                send_sms_remind(self, monitor)
        elif ntype == "close":
            send_class_closed_email(self, monitor)
            if self.unavailable_sms:
                send_sms_close(self, monitor)

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
        return "Unknown Role {}".format(self.role)

    def get_friendly_name(self):
        return "{}: {}".format(self.get_status(), self.email)

    def get_college(self):
        return get_user_college(self)

    def get_visible_users(self):
        if self.role <= ROLE_ADMIN:
            return User.query.all()
        if self.role <= ROLE_MARKETER:
            return User.query.filter_by(college=self.college).all()
        else:
            return [self]

    def get_visible_codes(self):
        if self.role <= ROLE_MARKETER:
            return FreePaymentCode.query.all()
        else:
            return FreePaymentCode.query.filter_by(creator_uuid=self.uuid).all()

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
        logger.debug("Created {}".format(self))

    def attempt_use(self, new_password):
        if self.used:
            logger.info("Attempted to reuse {}".format(self))
            return False
        if self.is_expired():
            age = (datetime.now() - self.created_at).total_seconds()
            logger.info("Attempted to use {}, expired by {} seconds".format(self, age - 600))
            return False
        user = User.query.filter_by(uuid=self.user_uuid).first()
        if user:
            user.bcrypt_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            self.used_at = datetime.now()
            self.used = True
            db.session.commit()
            logger.info("{} used {}".format(user, self))
            return True
        else:
            logger.info("Attempted to use {}, which did not have a corresponding user").format(self)
            return False

    def is_expired(self):
        age = (datetime.now() - self.created_at).total_seconds()
        return age > 600

    def __str__(self):
        user = User.query.filter_by(uuid=self.user_uuid).first()
        return "<PasswordResetRequest for {}>".format(user)


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
        logger.debug("{} created {}".format(creator, self))

    def delete(self):
        logger.debug("{} deleted".format(self))
        db.session.delete(self)
        db.session.commit()

    def get_user(self):
        return User.query.filter_by(uuid=self.used_by_uuid).first()

    def get_creator(self):
        return User.query.filter_by(uuid=self.creator_uuid).first()

    def use(self, user):
        if self.is_used:
            logger.info("Attempt to reuse {} by {}".format(self, user))
            return False
        else:
            self.used_by_uuid = user.uuid
            user.is_paid = True
            self.is_used = True
            self.used_on = datetime.now()
            transaction_info = "Used Free Payment Code '{}'<br>\n" \
                               "TIME: {}<br>\n".format(self.code,
                                                       self.used_on)
            send_activation_email(user, transaction_info)
            logger.info("{} used by {}".format(self, user))
            db.session.commit()
            return True

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

    def __init__(self, token, user):
        self.token = token
        self.account_uuid = user.uuid
        self.is_complete = False
        self.started_at = datetime.now()
        logger.info("Created {}".format(self))

    def process(self, transaction_info):
        if self.is_complete:
            logger.info("Attempt to reprocess {}".format(self))
            return False
        else:
            logger.info("Processed {}".format(self))
            user = User.query.filter_by(uuid=self.account_uuid).first()
            user.is_paid = True
            send_activation_email(user, transaction_info)
            self.is_complete = True
            self.completed_at = datetime.now()
            db.session.commit()
            return True

    def delete(self):
        if self.is_complete:
            logger.info("Attempt to cancel completed {}".format(self))
            return False
        else:
            db.session.delete(self)
            db.session.commit()
            logger.info("Deleted {}".format(self))
            return True

    def __str__(self):
        user = User.query.filter_by(uuid=self.account_uuid).first()
        return "<Payment for {} ({})>".format(user, self.token)


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
        logger.debug("Created {}".format(self))

    def update(self):
        logger.debug("Updating {}".format(self))
        delay_notify = datetime.now() - self.last_notified
        monitor = self.get_monitor()
        if monitor.has_availability:
            if self.notifications_sent == 0:
                self.notifications_sent += 1
                self.last_notified = datetime.now()
                user = self.get_requester()
                user.attempt_notify("open", monitor)
            elif delay_notify.total_seconds() > (59 * (2 ** self.notifications_sent) - 5):
                self.notifications_sent += 1
                self.last_notified = datetime.now()
                user = self.get_requester()
                user.attempt_notify("remind", monitor)
        else:
            if self.notifications_sent > 0:
                user = self.get_requester()
                user.attempt_notify("close", monitor)
            self.notifications_sent = 0

    def get_monitor(self):
        return ClassMonitor.query.filter_by(uuid=self.monitor_uuid).first()

    def get_requester(self):
        return User.query.filter_by(uuid=self.requester_uuid).first()

    def delete(self):
        logger.info("Deleting {}".format(self))
        if len(ClassRequest.query.filter_by(monitor_uuid=self.monitor_uuid).all()) == 1:
            monitor = self.get_monitor()
            logger.info("Only one request for {}, deleting monitor too.".format(monitor))
            monitor.delete()  # delete the class if this is the only request for it
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
        logger.debug("Created {}".format(self))

    @staticmethod
    def update_with_context(mon, app):
        with app.app_context():
            mon.update()

    def update(self):
        logger.debug("Updating {}".format(self))
        cl = self.class_instance
        self.has_availability = cl.update_status()
        self.class_instance = cl
        self.last_checked = datetime.now()
        requests = ClassRequest.query.filter_by(monitor_uuid=self.uuid).all()
        if len(requests) == 0:
            db.session.merge(self).delete()
            return
        db.session.merge(self)
        for request in requests:
            request.update()
            db.session.add(request)
        db.session.commit()

    def delete(self):
        logger.debug("Deleting {}".format(self))
        db.session.delete(self)
        db.session.commit()

    def __str__(self):
        return "<Monitor {}>".format(str(self.class_instance))


def update_all(app):
    global update_count
    update_count += 1
    update_id = update_count % 1000

    try:
        start = time.time()
        class_monitors = ClassMonitor.query.all()
        if len(class_monitors) == 0:
            return

        logger.debug("Updating {} monitors ({})".format(len(class_monitors), update_id))

        threads = list(threading.Thread(target=ClassMonitor.update_with_context, args=(monitor, app)) for monitor in
                       class_monitors)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        logger.debug("Updated {} listings in {:.4} seconds ({})".format(len(class_monitors), time.time() - start, update_id))

    except Exception:
        logger.exception("Error updating class monitors ({})".format(update_id))


def get_user(u):
    return User.query.filter_by(uuid=u).first()


from colleges import get_user_college
