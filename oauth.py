import os
from flask_dance.contrib.google import make_google_blueprint, google
from flask import url_for, redirect, session
from db import db, User
import logging
logger = logging.getLogger("app.google_oauth")


def setup(app):
    app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

    google_bp = make_google_blueprint(scope=["profile", "email"],
                                      redirect_to="google_signin")
    app.register_blueprint(google_bp, url_prefix="/login")

    @app.route("/api/google_signin", methods=["GET"])
    def google_signin():
        if not google.authorized:
            return redirect(url_for("google.login"))
        google_account = google.get("/oauth2/v1/userinfo").json()

        email = google_account["email"]
        user = User.query.filter_by(email=email).first()

        if user is not None:
            session["uuid"] = user.uuid
            logger.info("{} logged in with Google".format(user))
        else:
            # new account
            new_user = User("oauth", email, None)
            new_user.is_verified = True
            logger.info("New account created from OAuth login: {}".format(user))
            session["uuid"] = new_user.uuid
            db.session.add(new_user)
            db.session.commit()

        return redirect(url_for("landing_page"))




