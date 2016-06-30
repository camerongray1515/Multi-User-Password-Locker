from models import db_session, create_all, init, User, Folder, Permission
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

@server.route("/folders/add/", methods=["PUT"])
@auth_required
def folders_add(user):
    if not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "add a folder")

    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"}
        },
        "required": ["name"]
    }

    error = validate_schema(request.json, schema)
    if error:
        return error

    folder = request.json
    if Folder.query.filter(Folder.name==folder.get("name")).count():
        return error_response("already_exists", "A folder with that name "
            "already exists")

    f = Folder(name=folder.get("name"))
    db_session.add(f)

    # Give the creating user read/write permissions to the folder
    db_session.flush()
    db_session.add(Permission(read=True, write=True, user_id=user.id,
        folder_id=f.id))

    db_session.commit()

    return jsonify(success=True, folder_id=f.id)

@server.route("/folders/set_permissions/", methods=["POST"])
@auth_required
def folders_set_permissions(user):
    if not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "edit the permissions on a folder")

    schema = {
        "type": "object",
        "properies": {
            "folder_id": {"type": "integer"},
            "permissions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properies": {
                        "user_id": {"type": "integer"},
                        "read": {"type": "boolean"},
                        "write": {"type": "boolean"}
                    },
                    "required": ["user_id", "read", "write"]
                }
            }
        },
        "required": ["folder_id", "permissions"]
    }

    error = validate_schema(request.json, schema)
    if error:
        return error

    folder_id = request.json.get("folder_id")

    if not Folder.query.filter(Folder.id==folder_id).count():
        return error_response("item_not_found", "Folder not found")

    for permission in request.json.get("permissions"):
        user_id = permission.get("user_id")

        if not User.query.filter(User.id==user_id).count():
            return error_response("item_not_found", "User with ID {} not found"
                "".format(user_id))

        ps = Permission.query.filter(Permission.user_id==user_id).filter(
            Permission.folder_id==folder_id).all()
        p = ps[0] if ps else Permission()

        # If no read or write, do not add permission and delete if exists
        if not(permission.get("read") or permission.get("write")):
            if ps:
                db_session.delete(p)
            continue

        if permission.get("write") and not permission.get("read"):
            return error_response("input_validation_fail", "Users must be able "
                "to read a folder if they are to write to it")

        p.user_id = user_id
        p.folder_id = folder_id
        p.read = permission.get("read")
        p.write = permission.get("write")

        if not ps:
            db_session.add(p)

    db_session.commit()

    return jsonify(success=True)

@server.route("/folders/delete/<folder_id>/", methods=["DELETE"])
@auth_required
def folders_delete(folder_id, user):
    if not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "add a folder")

    f = Folder.query.get(folder_id)
    if not f:
        return error_response("item_not_found", "Folder not found")
    db_session.delete(f)
    db_session.commit()

    return jsonify(success=True)

@server.route("/folders/", methods=["GET"])
@auth_required
def folders(user):
    ps = Permission.query.filter(Permission.user_id==user.id).filter(
        Permission.read==True).all()

    folders = []
    for p in ps:
        f = p.folder
        folders.append({"id": f.id, "name": f.name, "read": p.read,
            "write": p.write})

    return jsonify(folders=folders)

@server.route("/users/", methods=["GET"])
@server.route("/users/<user_id>/", methods=["GET"])
@auth_required
def get_user(user, user_id=None):
    if not user_id:
        user_id = user.id
    user_id = int(user_id)

    if user_id != user.id and not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "get a user other than yourself")

    u = User.query.get(user_id)

    if not u:
        return error_response("item_not_found", "User not found")

    user = {
        "id": u.id,
        "full_name": u.full_name,
        "username": u.username,
        "email": u.email,
        "auth_hash": u.auth_hash,
        "encrypted_private_key": u.encrypted_private_key,
        "public_key": u.public_key,
        "admin": u.admin,
        "pbkdf2_salt": u.pbkdf2_salt,
        "aes_iv": u.aes_iv,
    }

    return jsonify(user=user)

@server.route("/folders/<folder_id>/public_keys/", methods=["GET"])
@auth_required
def folders_public_keys(user, folder_id):
    f = Folder.query.get(folder_id)
    if not f:
        return error_response("item_not_found", "Folder not found")

    public_keys = []

    for p in f.permissions:
        public_keys.append({
            "user_id": p.user.id,
            "public_key": p.user.public_key
        })

    return jsonify(public_keys=public_keys)
