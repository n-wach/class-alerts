from time import sleep

from flask import session, request, url_for, redirect, abort, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from db import get_user, db, attempt_get_user, User, ROLE_ADMIN, ClassRequest, ROLE_MARKETER, FreePaymentCode, \
    PasswordResetRequest
from notifier import send_verification_email, send_password_reset_email, send_contact_email
from app import MAX_USER_REQUESTS
from colleges import college_short_names, get_user_college
from decorators import requires_signin, requires_form_field, PATTERN_NOT_EMPTY, errors, PATTERN_PHONE, \
    requires_verified, PATTERN_UUID, requires_paid, PATTERN_MASS_MESSAGE, requires_role, PATTERN_EMAIL, PATTERN_CODE, \
    PATTERN_PASSWORD

import logging
logger = logging.getLogger("app.api")


def route(app):
    limiter = Limiter(app, key_func=get_remote_address, default_limits=["100 per hour", "10 per second"])
    for handler in logger.handlers:
        limiter.logger.addHandler(handler)

    @app.route("/api/signin", methods=["POST"])
    @requires_form_field("email", if_missing="Email missing", redirect_url_for="login",
                         value_pattern=PATTERN_NOT_EMPTY)
    @requires_form_field("password", if_missing="Password missing", redirect_url_for="login",
                         value_pattern=PATTERN_NOT_EMPTY, repopulate=False)
    @limiter.limit("10 per hour")
    def do_signin():
        login_pw = request.form.get("password")
        login_email = request.form.get("email").lower()

        user = User.query.filter_by(email=login_email).first()
        if user is not None and user.verify_password(login_pw):
            session["uuid"] = user.uuid
            logger.info("{} logged in".format(user))
            return redirect(url_for("landing_page"))

        return errors("Invalid Email or Password", "signin")

    @app.route("/api/signup", methods=["POST"])
    @requires_form_field("email", if_missing="Email missing", redirect_url_for="signup", value_pattern=PATTERN_EMAIL)
    @requires_form_field("password", if_missing="Password missing", redirect_url_for="signup",
                         value_pattern=PATTERN_NOT_EMPTY, repopulate=False)
    @requires_form_field("confirm", if_missing="Password confirmation missing", redirect_url_for="signup",
                         value_pattern=PATTERN_NOT_EMPTY, repopulate=False)
    @limiter.limit("5 per day")
    def do_signup():
        create_email = request.form.get("email").lower()
        create_pw = request.form.get("password")
        confirm_pw = request.form.get("confirm")
        create_phone = request.form.get("phone")
        match = User.query.filter_by(email=create_email).first()

        if match is not None:
            return errors("This email is already in use.  Please use a different one or sign in.", "signup")
        elif len(create_pw) < 6:
            return errors("Password must be at least 6 characters long.", "signup")
        elif create_pw != confirm_pw:
            return errors("Passwords do not match.", "signup")
        elif create_phone != "" and (len(create_phone) != 11 or not PATTERN_PHONE.match(create_phone)):
            return errors("Invalid phone number format.", "signup")

        user = User("root", create_email, create_phone, create_pw)
        session["uuid"] = user.uuid

        if len(User.query.all()) == 0:
            user.role = ROLE_ADMIN
            user.is_verified = True
            user.is_paid = True
            logger.warning("First user {} created and given ROLE_ADMIN".format(user))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("landing_page"))
        else:
            logging.info("New user {} created".format(user))
            db.session.add(user)
            db.session.commit()
            send_verification_email(user)
            return redirect(url_for("verify"))

    @app.route("/api/user/verify-email/<code>")
    @requires_signin
    @requires_verified(False)
    @limiter.limit("20 per day")
    def do_verify(code):
        user = get_user(session["uuid"])
        if not PATTERN_UUID.match(code):
            logger.info("Malformed or missing verify code '{}' from {}".format(code, user))
            return errors("Verification code missing or invalid format.  Please try again or contact support", "verify_page")
        if code == user.verify_code:
            user.is_verified = True
            db.session.commit()
        else:
            logger.info("Invalid verify code '{}' from {}".format(code, user))
            return errors("Verification failed.  Please try again or contact support", "verify_page")
        return redirect(url_for("landing_page"))

    @app.route("/api/user/choose-college", methods=["POST"])
    @requires_signin
    @requires_form_field("college", if_missing="College missing", redirect_url_for="landing_page",
                         value_pattern=PATTERN_NOT_EMPTY)
    @limiter.limit("20 per day")
    def do_college_select():
        user = get_user(session["uuid"])
        college = request.form.get("college")
        ret = request.form.get("ret", url_for("landing_page"))
        if college in college_short_names:
            user.college = college
            logger.info("{} changed their college to {}".format(user, college))
            db.session.commit()
            for req in user.get_requests():
                if req.college != college:
                    logger.info("Deleting {} because of college change".format(req))
                    req.delete()
            return redirect(ret)
        else:
            logger.debug("Invalid choose-college: '{}' for {}".format(college, user))
            abort(400, "College not found")

    @app.route("/api/classes/add", methods=["POST"])
    @requires_signin
    @requires_paid(True)
    @limiter.limit("20 per day")
    def do_add():
        user = get_user(session["uuid"])
        college = get_user_college(user)
        try:
            verified = college.verify_add_request(request.form)
            if verified is not True:
                logger.info("Invalid add request '{}' for {} by {}".format(request.form, college, user))
                return errors("Invalid add request", "add")

            class_monitor = college.monitor_from_add_request(request)

            if len(ClassRequest.query.filter_by(monitor_uuid=class_monitor.uuid, requester_uuid=user.uuid).all()) > 0:
                logger.info("Duplicate add request for {} by {}".format(class_monitor, user))
                return errors("You've already added this class!", "add")
            elif len(user.get_requests()) >= MAX_USER_REQUESTS:
                logger.info("Attempt to request more than {} classes by {}".format(MAX_USER_REQUESTS, user))
                return errors("You can't request more than {} classes at a time.".format(MAX_USER_REQUESTS), "add")
            else:
                req = ClassRequest(user, class_monitor)
                db.session.add(req)
                db.session.commit()
                logger.info("{} added {}".format(user, req))
                return redirect(url_for("landing_page"))
        except Exception as e:
            logger.exception("Error adding class for {} at {} with request '{}'".format(user, college, request.form))
            return errors("We're sorry. Something went wrong when adding that class. Make sure everything is correct, "
                          "then contact support.", "add")

    @app.route("/api/classes/remove", methods=["POST"])
    @requires_signin
    def do_remove_class():
        user = get_user(session["uuid"])
        try:
            monitor_uuid = request.form.get("uuid")
            req = ClassRequest.query.filter_by(requester_uuid=user.uuid, monitor_uuid=monitor_uuid).first()
            req.delete()
            logger.info("{} removed {}".format(user, req))
        except Exception as e:
            logger.exception("Error removing class with UUID {} from {}".format(request.form.get("uuid"), user))
            abort(400, "Class info is invalid")
        return redirect(url_for("landing_page"))

    @app.route("/api/admin/message", methods=["POST"])
    @requires_role(ROLE_ADMIN)
    @requires_form_field("message", if_missing="Missing message", redirect_url_for="message",
                         value_pattern=PATTERN_MASS_MESSAGE, if_invalid="Message too short!")
    @limiter.limit("5 per hour")
    def do_message():
        raise NotImplementedError("Message function temporarily disabled")

    @app.route("/api/admin/generate-free-code", methods=["POST"])
    @requires_role(ROLE_MARKETER)
    @requires_form_field("code", if_missing="Missing code", redirect_url_for="view_codes",
                         value_pattern=PATTERN_CODE,
                         if_invalid="Codes must be at least 5 characters (letters and numbers only)")
    def do_generate_free_code():
        user = get_user(session["uuid"])
        code = request.form.get("code").lower()
        if len(FreePaymentCode.query.filter_by(code=code).all()) > 0:
            logging.info("{} tried to generate existing code '{}'".format(user, code))
            return errors("Code has already been generated.", "view_codes")
        else:
            p = FreePaymentCode(code, user)
            logger.info("{} generated code {}".format(user, p))
            db.session.add(p)
            db.session.commit()
            return redirect(url_for("view_codes"))

    @app.route("/api/user/use-free-code", methods=["POST"])
    @requires_paid(paid=False)
    @requires_form_field("code", if_missing="Missing code", redirect_url_for="view_codes",
                         value_pattern=PATTERN_CODE, if_invalid="Codes must be at least 5 characters (letters and numbers only)")
    @limiter.limit("20 per day")
    def do_use_free_code():
        user = get_user(session["uuid"])
        code = request.form.get("code").lower()
        fpc = FreePaymentCode.query.filter_by(code=code).first()
        if fpc is None:
            logger.info("{} tried using non-existent code '{}'".format(user, code))
            return errors("Code does not exist", "renew")
        elif fpc.is_used:
            logger.info("{} tried using expired code '{}'").format(user, code)
            return errors("Code has already been used", "renew")
        else:
            fpc.use(user)
            logger.info("{} used {}".format(user, fpc))
            return redirect(url_for("landing_page"))

    @app.route("/api/admin/delete-free-code", methods=["POST"])
    @requires_role(ROLE_MARKETER)
    @requires_form_field("delete-code", if_missing="Missing code", redirect_url_for="view_codes",
                         value_pattern=PATTERN_CODE, if_invalid="Codes must be at least 5 characters (letters and numbers only)")
    def do_delete_code():
        user = get_user(session["uuid"])
        code = request.form.get("delete-code").lower()
        if len(FreePaymentCode.query.filter_by(code=code).all()) == 0:
            logger.info("{} tried deleting non-existent code '{}'".format(user, code))
            return errors("Code does not exist.", "view_codes")
        else:
            fpc = FreePaymentCode.query.filter_by(code=code).first()
            if fpc.is_used:
                logger.info("{} tried deleting consumed code '{}'".format(user, code))
                return errors("Code has already been used, and cannot be deleted.", "view_codes")
            else:
                logger.info("{} deleted {}".format(user, fpc))
                fpc.delete()
                db.session.commit()
                return redirect(url_for("view_codes"))

    @app.route("/api/admin/set-paid", methods=["POST"])
    @requires_role(ROLE_MARKETER)
    def set_paid():
        target = get_user(request.form.get("target-uuid"))
        is_paid = request.form.get("is-paid") == "true"
        user = get_user(session["uuid"])
        if user.role < target.role:
            logger.info("{} set {} to {}".format(user, target, "paid" if is_paid else "unpaid"))
            target.is_paid = is_paid
            db.session.commit()
            return redirect(url_for("view_all"))
        else:
            logger.info("{} failed to set {} to {} because of insufficient role".format(user, target, "paid" if is_paid else "unpaid"))
            return abort(403, "Insufficient Role")

    @app.route("/api/user/forgot-password", methods=["POST"])
    @requires_form_field("email", if_missing="Email missing", redirect_url_for="forgot_page",
                         value_pattern=PATTERN_EMAIL)
    @limiter.limit("5 per hour")
    def forgot():
        email = request.form.get("email").lower()
        user = User.query.filter_by(email=email).first()
        if user:
            prr = PasswordResetRequest(user.uuid)
            db.session.add(prr)
            db.session.commit()
            logger.info("Someone requested password reset for {}".format(user))
            send_password_reset_email(user, prr)
        else:
            logger.info("Someone requested password reset for email {}, which does not exist".format(email))
            sleep(1)
        return render_template("public/forgot-response.html", forgot_email=email)

    @app.route("/api/user/reset-password/<reset_uuid>", methods=["POST"])
    @limiter.limit("5 per hour")
    def reset_password(reset_uuid):
        password = request.form.get("password", "")
        c_password = request.form.get("c_password", "")
        # we should check password first to avoid leaking whether UUID is valid PRR
        if len(password) < 6:
            logger.info("Password reset for uuid {} failed: invalid length".format(reset_uuid))
            return errors("Password must be at least 6 characters", "reset_password_page", reset_uuid=reset_uuid)
        if password != c_password:
            logger.info("Password reset for uuid {} failed: no match".format(reset_uuid))
            return errors("Passwords do not match", "reset_password_page", reset_uuid=reset_uuid)

        prr = PasswordResetRequest.query.filter_by(uuid=reset_uuid).first()
        if not prr:
            logger.info("Attempt to use non-existent reset UUID: {}".format(reset_uuid))
            return errors("Invalid or Expired Reset Code", "reset_password_page", reset_uuid=reset_uuid)
        else:
            if prr.attempt_use(password):
                logger.info("Successfully used {}".format(prr))
                return errors("Password reset", "signin")
            else:
                logger.info("Attempt to use expired {}".format(prr))
                return errors("Invalid or Expired Reset Code", "reset_password_page", reset_uuid=reset_uuid)

    @app.route("/api/admin/delete-uuid", methods=["POST"])
    @requires_signin
    @requires_role(ROLE_MARKETER)
    def delete_uuid():
        user = get_user(session["uuid"])
        to_delete = get_user(request.form("delete-uuid"))
        if not to_delete:
            abort(400, "Invalid UUID")

        if user is to_delete:
            return redirect(url_for("settings_page", prop="delete"))

        if user.role < to_delete.role:
            to_delete.delete()
            logger.info("{} deleted user {}".format(user, to_delete))
            return redirect(url_for("view_all"))
        else:
            logger.info("{} attempted to delete {} but had an insufficient role".format(user, to_delete))
            abort(401, "Insufficient Role")

    @app.route("/api/user/delete-me", methods=["POST"])
    @requires_signin
    def delete_me():
        user = get_user(session["uuid"])
        if session["confirm-delete"] == "yes":
            session.clear()
            user.delete()
            logger.info("{} deleted their account".format(user))
            return errors("Your account has been deleted", "sign-up")
        else:
            logger.info("{} failed to delete their account".format(user))
            abort(400, "Something went wrong.")

    @app.route("/api/user/settings/<prop>", methods=["POST"])
    @requires_signin
    def update_settings(prop):
        user = get_user(session.get("uuid"))

        if prop == "password":
            old_password = request.form.get("o_pw")
            new_password_1 = request.form.get("n_pw_1")
            new_password_2 = request.form.get("n_pw_2")
            if user.verify_password(old_password):
                if new_password_1 != new_password_2:
                    logger.info("{} failed to change their password: passwords do not match".format(user))
                    return errors("New passwords do not match", "settings", prop="password")
                elif not PATTERN_PASSWORD.match(new_password_1):
                    logger.info("{} failed to change their password: invalid password length".format(user))
                    return errors("Password must be at least 6 characters long", "settings", prop="password")
                else:
                    user.set_password(new_password_1)
                    logger.info("{} changed their password".format(user))
                    db.session.commit()
                    return redirect(url_for("settings", prop="password"))
            else:
                logger.info("{} failed to change their password: invalid old password".format(user))
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
                    logger.info("{} changed their phone number to '{}'".format(user, phone))
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
                logger.info("{} updated their notification settings".format(user))
                return redirect(url_for("settings", prop="notification"))
            else:
                logger.info("{} failed to change their phone number to '{}': invalid format".format(user, phone))
                return errors("Invalid phone", "settings", prop="notification")
        elif prop == "delete":
            logger.info("{} is going to delete their account".format(user))
            session["confirm-delete"] = "yes"
            return redirect(url_for("delete_me"))
        else:
            return errors("Nothing to update", "settings")

    @app.route("/api/signout")
    def signout():
        user = get_user(session["uuid"])
        session.clear()
        logger.info("Logged out {}".format(user))
        return redirect(url_for("landing_page"))

    @app.route("/api/contact", methods=["POST"])
    @requires_form_field("email", if_missing="Email missing", redirect_url_for="contact_page",
                         value_pattern=PATTERN_EMAIL)
    @requires_form_field("subject", if_missing="Subject missing", redirect_url_for="contact_page",
                         value_pattern=PATTERN_NOT_EMPTY)
    @requires_form_field("message", if_missing="Message missing", redirect_url_for="contact_page",
                         value_pattern=PATTERN_NOT_EMPTY)
    @limiter.limit("5 per day")
    def contact():
        email = request.form.get("email")
        subject = request.form.get("subject", "No Subject")
        msg = request.form.get("message")
        logger.info("{} sending contact email with subject '{}'".format(email, subject))
        send_contact_email(email, subject, msg)
        return errors("Your message has been sent", "contact_page")

