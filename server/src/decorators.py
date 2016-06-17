import bcrypt
from models import db_session, User
from flask import request, Response
from functools import wraps

def auth_required(admin_required=False):
    def fail_auth():
        return Response('Authentication required!', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})

    def decorator(func):
        @wraps(func)
        def decorated(*args, **kwargs):
            auth = request.authorization
            print(auth)
            if not auth:
                return fail_auth()
            u = User.query.filter(User.username==auth.username).all()
            print(auth.username)
            print(auth.password)
            if len(u) > 0:
                user = u[0]
                if bcrypt.hashpw(auth.password.encode("UTF-8"),
                    user.auth_hash) == user.auth_hash:
                    if admin_required and not user.admin:
                        return fail_auth()
                    return func(*args, **kwargs)
            else:
                return fail_auth()

        return decorated
    return decorator
