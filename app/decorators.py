from functools import wraps
from flask import abort
from flask_login import current_user  # current_user delegate user who visit webs
from .models import Permission


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
                # server understand the request, but reject to execute
                # differ to 401, authentication cant solve problem,
                # and the request should not submit repeatedly
            return f(*args, **kwargs)

        return decorated_function

    return decorator