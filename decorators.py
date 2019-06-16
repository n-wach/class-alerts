from functools import wraps

from flask import session, url_for, abort, redirect, request

from DB import get_user


def errors(error, return_page, **kwargs):
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


def requires_form_field(name, if_missing, redirect_url_for=None, value_pattern=None, if_invalid=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            value = request.form.get(name)
            error_message = None
            if value is None:
                error_message = if_missing

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
