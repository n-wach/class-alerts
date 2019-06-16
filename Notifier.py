import os
import smtplib
# from urllib import quote_plus
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
from datetime import datetime
from flask import url_for
from twilio.rest import Client

sms_sid = os.environ.get("SMS_SID")
sms_auth = os.environ.get("SMS_AUTH")
sms_sender = "+18056181459"
SEND_SMS = False

email_sender = "Class Alerts <info@m.classalerts.org>"
email_api_key = os.environ.get("EMAIL_API_KEY")
email_url = "https://api.mailgun.net/v3/m.classalerts.org/messages"

client = Client(sms_sid, sms_auth)


TEMPLATE_VERIFICATION = None
TEMPLATE_ACTIVATED = None
TEMPLATE_DEACTIVATED = None
TEMPLATE_CLASS_STATUS_OPEN = None
TEMPLATE_CLASS_STATUS_CLOSE = None
TEMPLATE_PASSWORD_RESET_REQUEST = None
TEMPLATE_PASSWORD_CHANGE = None
app = None


def prepare_templates(a):
    global app
    app = a

    global TEMPLATE_VERIFICATION
    global TEMPLATE_ACTIVATED
    global TEMPLATE_DEACTIVATED
    global TEMPLATE_CLASS_STATUS_OPEN
    global TEMPLATE_CLASS_STATUS_CLOSE
    global TEMPLATE_PASSWORD_RESET_REQUEST
    global TEMPLATE_PASSWORD_CHANGE

    TEMPLATE_VERIFICATION = app.jinja_env.get_template("email/verification.html")
    TEMPLATE_ACTIVATED = app.jinja_env.get_template("email/activated.html")
    TEMPLATE_DEACTIVATED = app.jinja_env.get_template("email/deactivated.html")
    TEMPLATE_CLASS_STATUS_OPEN = app.jinja_env.get_template("email/class-open.html")
    TEMPLATE_CLASS_STATUS_CLOSE = app.jinja_env.get_template("email/class-close.html")
    TEMPLATE_PASSWORD_RESET_REQUEST = app.jinja_env.get_template("email/password-reset-request.html")
    TEMPLATE_PASSWORD_CHANGE = app.jinja_env.get_template("email/password-change.html")


def send_sms(raw_phone, message):
    if len(str(raw_phone)) != 11:
        return None
    if SEND_SMS:
        client.messages.create(
            to="+" + str(raw_phone),
            body=message,
            from_=sms_sender)
        print("Message sent to " + str(raw_phone))
    else:
        print("Pretend a message was sent to " + str(raw_phone))


def send_call(raw_phone):
    if len(str(raw_phone)) != 11:
        return None
    if SEND_SMS:
        client.calls.create(
            to="+" + str(raw_phone),
            from_=sms_sender)
        print("Message sent to " + str(raw_phone))
    else:
        print("Pretend a call was sent to " + str(raw_phone))


def send_test():
    client.calls.create(
        to="+18055709334",
        from_=sms_sender,
        url="http://classalerts.org/voice/available.xml")


def send_email(recipient, subject, html=None, plain="Email only available in html format."):
    if html:
        return requests.post(
            email_url,
            auth=("api", email_api_key),
            data={"from": email_sender,
                  "to": [recipient],
                  "subject": subject,
                  "text": plain,
                  "html": html
                  }
        )
    else:
        return requests.post(
            email_url,
            auth=("api", email_api_key),
            data={"from": email_sender,
                  "to": [recipient],
                  "subject": subject,
                  "text": plain,
                  }
        )


def send_verification_email(user):
    send_email(user.email, "Verify Your Email",
               TEMPLATE_VERIFICATION.render(user=user),
               "Verification Link: " + url_for("do_verify", code=user.verify_code, _external=True))


def send_activation_email(user):
    send_email(user.email, "Account Activated",
               TEMPLATE_ACTIVATED.render(user=user),
               "Account activated!")


def send_deactivation_email(user):
    send_email(user.email, "Renew Your Account!",
               TEMPLATE_DEACTIVATED.render(user=user),
               "Renew your account.")


def send_class_open_email(user, class_monitor):
    send_email(user.email, "Open: " + class_monitor.class_instance.display_name,
               TEMPLATE_CLASS_STATUS_OPEN.render(user=user, class_monitor=class_monitor),
               "Class open!\n{}\nRegister: {}".format(class_monitor.class_instance.status_message,
                                                      class_monitor.class_instance.action_url))


def send_class_closed_email(user, class_monitor):
    send_email(user.email, "Closed: " + class_monitor.class_instance.display_name,
               TEMPLATE_CLASS_STATUS_CLOSE.render(user=user, class_monitor=class_monitor),
               "Class Closed.\n{}".format(class_monitor.class_instance.status_message))


def send_password_reset_email(user, prr):
    send_email(user.email, "Password Reset",
               TEMPLATE_PASSWORD_RESET_REQUEST.render(user=user, prr=prr),
               "Password Reset Link: " + url_for("reset_password", reset_uuid=prr.uuid, _external=True))


def send_password_change_email(user):
    send_email(user.email, "Password Change",
               TEMPLATE_PASSWORD_CHANGE.render(user=user),
               "Your password has changed.  Contact us immediately if you did not change your password.")


def send_contact_email(email, subject, msg):
    i_subject = "Message from <{}>: [{}]".format(email, subject)
    plain = ("Sent at {}\n" +
             "From {}\n\n" +
             "Subject: {}\n" +
             "Message: \n\n" +
             "{}").format(str(datetime.now()), email, subject, msg)
    send_email("nmwachholz@gmail.com", i_subject, plain=plain)
    o_subject = "Confirming Receipt of Contact Message: [{}]".format(subject)
    send_email(email, o_subject, plain=plain)
