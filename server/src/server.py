from models import db_session, create_all, init, User, Folder
from flask import Flask, jsonify, request, make_response
from decorators import auth_required
from validation import error_response, validate_schema

server = Flask(__name__)

# Methods required:
#   - Create a new folder, only for admins
#   - Set permissions for user on a folder, if read and write false, remove
#       entry.  Only for admins
#   - Add new account to a folder, only for users who can edit
#   - Delete account, only for users who can edit
#   - Get all public keys for an account, only for users who can edit
#   - Update encrypted data for an account, only for users who can edit
#       or own account
#   - Update public, encrypted private key pair and auth key (hashed server
#       side), only for authenticated user
#   - Get metadata for all accounts in a folder, only for authenticated user
#   - Get password for an account, only for authenticated user
#   - Get encrypted private key for a user, only for authenticated user
#   - Get all folders, only for authenticated user
#
# Also need an endpoint where multiple updates can be sent in a single request
# to be carried out.  Some operations such as changing a user password will
# require many different fields to be updated, this must be done in a single
# request so that if the client disconnects the database cannot be left in a
# half-updated state.  Break out actual update logic into own method that does
# not commit session.  Commit is then performed separately when all updates have
# completed.
#

@server.route("/")
@auth_required(admin_required=True)
def index(user):
    return jsonify([{"email": user.email}])

@server.route("/folder/add/", methods=["POST"])
@auth_required(admin_required=True)
def folder_add(user):
    if not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "add a folder")

    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            }
        }
    }

    error = validate_schema(request.json, schema)
    if error:
        return error

    for f in request.json:
        if Folder.query.filter(Folder.name==f.get("name")).count():
            db_session.rollback()
            return error_response("already_exists", "A folder with that name "
                "already exists")

        db_session.add(Folder(name=f.get("name")))

    db_session.commit()

    return jsonify(success=True)
