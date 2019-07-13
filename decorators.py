import re
from functools import wraps

from flask import session, url_for, abort, redirect, request

from db import get_user

import logging

logger = logging.getLogger("app.decorators")


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


def errors(error, return_page, **kwargs):
    logger.debug("Redirecting to '{}' with error '{}'".format(return_page, error))
    session["display_error"] = error
    return redirect(url_for(return_page, **kwargs))


def requires_signin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "uuid" not in session:

            return redirect(url_for("signin"))
        else:
            user = get_user(session["uuid"])
            if user is not None:
                return f(*args, **kwargs)
            else:
                session.clear()
                return redirect(url_for("signin"))

    return wrapper


def requires_role(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "uuid" not in session:
                return abort(404)
            else:
                user = get_user(session["uuid"])
                if user is not None and user.role <= role:
                    return f(*args, **kwargs)
                else:
                    return abort(404)
        return wrapper
    return decorator


def requires_form_field(name, if_missing, redirect_url_for=None, value_pattern=None, if_invalid=None, repopulate=True):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            value = request.form.get(name)
            error_message = None
            if value is None:
                error_message = if_missing
            elif repopulate:
                repopulate_form = session.get("repopulate_form", {})
                repopulate_form[name] = value
                session["repopulate_form"] = repopulate_form

            elif value_pattern is not None:
                if not value_pattern.match(value):
                    if if_invalid is not None:
                        error_message = if_invalid
                    else:
                        error_message = if_missing

            if error_message is not None:
                # error
                if redirect_url_for is not None:
                    return errors(error_message, redirect_url_for)
                else:
                    return error_message
            else:
                # call
                return f(*args, **kwargs)

        return wrapper

    return decorator


def displays_error(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        error = session.get("display_error")
        session["display_error"] = ""
        return f(*args, **kwargs, error=error)

    return wrapper


def requires_verified(verified=True):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_user(session["uuid"])
            if user.is_verified == verified:
                return f(*args, **kwargs)
            else:
                return abort(404)

        return wrapper

    return decorator


def requires_paid(paid=True):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_user(session["uuid"])
            if user.is_paid == paid:
                return f(*args, **kwargs)
            else:
                return abort(404)

        return wrapper

    return decorator
