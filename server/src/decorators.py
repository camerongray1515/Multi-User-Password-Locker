import bcrypt
from models import db_session, User
from flask import request, Response
from functools import wraps

def fail_auth():
    return Response('Authentication required!', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

def auth_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            return fail_auth()
        u = User.query.filter(User.username==auth.username).all()
        if len(u) > 0:
            user = u[0]
            auth_hash = user.auth_hash.encode("UTF-8")
            if bcrypt.hashpw(auth.password.encode("UTF-8"),
                auth_hash) == auth_hash:
                return func(*args, user=user, **kwargs)
            else:
                return fail_auth()
        else:
            return fail_auth()

    return decorated
