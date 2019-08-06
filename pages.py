from flask import render_template, session, redirect, url_for, abort, request

from db import get_user, ROLE_ADMIN, ROLE_MARKETER
from colleges import college_short_names
from decorators import requires_signin, displays_error, requires_verified, requires_role, requires_paid


def route(app):
    @app.route("/", methods=["GET"])
    def landing_page():
        if "uuid" not in session:
            return render_template("public/about.html")

        user = get_user(session["uuid"])
        if user is None:
            del session["uuid"]
            return render_template("public/about.html")
        elif not user.is_verified:
            return redirect(url_for("verify_email"))
        elif user.college not in college_short_names:
            return redirect(url_for("college_select"))
        return render_template("user/home.html")

    @app.route("/signin", methods=["GET"])
    @displays_error
    def signin(error):
        if "uuid" in session:
            return redirect(url_for("landing_page"))
        return render_template("public/sign-in.html", error=error)

    @app.route("/signup", methods=["GET"])
    @displays_error
    def signup(error):
        if "uuid" in session:
            return redirect(url_for("landing_page"))
        return render_template("public/sign-up.html", error=error)

    @app.route("/verify-email", methods=["GET"])
    @requires_signin
    @requires_verified(False)
    @displays_error
    def verify_email(error):
        return render_template("user/verify.html", error=error)

    @app.route("/choose-college", methods=["GET"])
    @requires_signin
    def college_select():
        user = get_user(session["uuid"])
        if user.is_paid and user.get_college() is not None and user.role > ROLE_ADMIN:
            return redirect(url_for("landing_page"))
        return render_template("user/college-selection.html")

    @app.route("/classes/add", methods=["GET"])
    @requires_signin
    @requires_paid(True)
    @displays_error
    def class_add(error):
        return render_template("user/add.html", error=error)

    @app.route("/admin/message", methods=["GET"])
    @requires_role(ROLE_ADMIN)
    @displays_error
    def admin_message(error):
        return render_template("admin/mass-message.html", error=error)

    @app.route("/admin/codes", methods=["GET"])
    @requires_role(ROLE_MARKETER)
    @displays_error
    def admin_codes_view(error):
        return render_template("admin/view-codes.html", error=error)

    @app.route("/admin/view-accounts", methods=["GET"])
    @requires_role(ROLE_ADMIN)
    def admin_users_view():
        return render_template("admin/view-accounts.html")

    @app.route("/forgot-password", methods=["GET"])
    @displays_error
    def forgot_password(error):
        e = session.get("forgot-password-email", None)
        if e:
            session["forgot-password-email"] = None
            return render_template("public/forgot-response.html", forgot_email=e)
        else:
            return render_template("public/forgot.html", error=error)

    @app.route("/reset-password/<reset_uuid>", methods=["GET"])
    @displays_error
    def reset_password(error, reset_uuid):
        return render_template("public/set-password.html", reset_uuid=reset_uuid, error=error)

    @app.route("/settings/<prop>", methods=["GET"])
    @requires_signin
    @displays_error
    def settings(error, prop):
        if prop == "password":
            return render_template("user/settings/password.html", error=error)
        elif prop == "notification":
            return render_template("user/settings/notification.html", error=error)
        elif prop == "delete":
            return render_template("user/settings/delete.html", error=error)
        else:
            return render_template("user/settings/settings.html", error=error)

    @app.route("/settings", methods=["GET"])
    @requires_signin
    @displays_error
    def settings_list(error):
        return render_template("user/settings/settings.html", error=error)

    @app.route("/activate", methods=["GET"])
    @requires_paid(False)
    @displays_error
    def activate(error):
        return render_template("user/activate.html", error=error)

    @app.route("/contact", methods=["GET"])
    @displays_error
    def contact_page(error):
        return render_template("public/contact.html", error=error)

    @app.route("/request", methods=["GET"])
    @displays_error
    def college_request_page(error):
        return render_template("public/contact.html", error=error, college_request=True)

    @app.route("/privacy", methods=["GET"])
    def privacy_page():
        return render_template("public/privacy.html")

    @app.route("/terms", methods=["GET"])
    def terms_page():
        return render_template("public/terms.html")

    @app.route("/about", methods=["GET"])
    def about_page():
        return render_template("public/about.html")

    @app.route("/echo", methods=["GET"])
    def echo():
        print("ECHO CALLED {}".format(request.url))
        print("ARGS: {}".format(request.args))
        abort(404)

