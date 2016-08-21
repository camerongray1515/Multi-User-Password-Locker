from models import db_session, create_all, init, User, Folder, Permission,\
    Account, AccountDataItem
from flask import Flask, jsonify, request, make_response
from decorators import auth_required
from validation import error_response, validate_schema
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
import bcrypt

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

@server.route("/folders/", methods=["PUT"])
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

    if not folder.get("name").strip():
        return error_response("input_validation_fail", "You must supply a name "
            "for this folder");

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

# TODO: Remove /save from URL
@server.route("/folders/<folder_id>/save/", methods=["POST"])
@auth_required
def folders_save(user, folder_id):
    if not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "update a folder")

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

    f = Folder.query.get(folder_id)
    if not f:
        return error_response("item_not_found", "Folder not found")

    folder = request.json

    if not folder.get("name").strip():
        return error_response("input_validation_fail", "You must supply a name "
            "for this folder");

    if Folder.query.filter(Folder.name==folder.get("name")).filter(
        Folder.id!=folder_id).count():
        return error_response("already_exists", "A folder with that name "
            "already exists")

    f.name = folder.get("name")
    db_session.commit()

    return jsonify(success=True)

# TODO: Change URL to /folders/<folder_id>/
@server.route("/folders/delete/<folder_id>/", methods=["DELETE"])
@auth_required
def folders_delete(folder_id, user):
    if not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "delete a folder")

    f = Folder.query.get(folder_id)
    if not f:
        return error_response("item_not_found", "Folder not found")
    db_session.delete(f)
    db_session.commit()

    return jsonify(success=True)

@server.route("/folders/", methods=["GET"])
@auth_required
def folders(user):
    folders = []
    if user.admin:
        for f in Folder.query.all():
            folders.append({"id": f.id, "name": f.name, "read": True,
                "write": True})
    else:
        ps = Permission.query.filter(Permission.user_id==user.id).filter(
            Permission.read==True).all()
        for p in ps:
            f = p.folder
            folders.append({"id": f.id, "name": f.name, "read": p.read,
                "write": p.write})

    return jsonify(folders=folders)

@server.route("/users/<user_id>/", methods=["GET"])
@auth_required
def get_user(user, user_id=None):
    if user_id == "self":
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

@server.route("/users/<user_id>/encrypted_aes_keys/", methods=["GET"])
@auth_required
def get_encrypted_aes_keys(user, user_id=None):
    if user_id == "self":
        user_id = user.id
    user_id = int(user_id)

    if user_id != user.id and not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "set keys for a user other than yourself")

    account_data_items = AccountDataItem.query.filter(
        AccountDataItem.user_id == user_id)

    encrypted_aes_keys = []
    for item in account_data_items:
        encrypted_aes_keys.append({
            "account_id": item.account.id,
            "encrypted_aes_key": item.encrypted_aes_key,
        })

    return jsonify(encrypted_aes_keys=encrypted_aes_keys)

# # TODO - Include some way to change user's stored auth hash at the same time!
# @server.route("/users/<user_id>/encrypted_aes_keys/", methods=["POST"])
# @auth_required
# def update_encrypted_aes_keys(user, user_id=None):
#     if user_id == "self":
#         user_id = user.id
#     user_id = int(user_id)
#
#     if user_id != user.id and not user.admin:
#         return error_response("not_admin", "You must be an administrator to "
#             "get keys for a user other than yourself")
#
#     schema = {
#         "type": "array",
#         "items": {
#             "type": "object",
#             "properties": {
#                 "account_id": {"type": "integer"},
#                 "encrypted_aes_key": {"type": "string"},
#             },
#             "required": ["account_id", "encrypted_aes_key"]
#         }
#     }
#
#     error = validate_schema(request.json, schema)
#     if error:
#         return error
#
#     keys = {}
#     for item in request.json:
#         keys[item["account_id"]] = item["encrypted_aes_key"]
#
#     account_data_items = AccountDataItem.query.filter(
#         AccountDataItem.user_id == user_id)
#
#     for item in account_data_items:
#         item.encrypted_aes_key = keys[item.account.id]
#
#     db_session.commit()
#
#     return jsonify(success=True)

@server.route("/users/self/update_password/", methods=["POST"])
@auth_required
def users_self_update_password(user):
    schema = {
        "type": "object",
        "properties": {
            "encrypted_private_key": {"type": "string"},
            "aes_iv": {"type": "string"},
            "pbkdf2_salt": {"type": "string"},
            "auth_key": {"type": "string"},
        },
        "required": ["encrypted_private_key", "aes_iv", "pbkdf2_salt",
            "auth_key"]
    }

    error = validate_schema(request.json, schema)
    if error:
        return error

    u = User.query.get(user.id)

    user.encrypted_private_key = request.json["encrypted_private_key"]
    user.aes_iv = request.json["aes_iv"]
    user.pbkdf2_salt = request.json["pbkdf2_salt"]
    user.auth_hash = bcrypt.hashpw(request.json["auth_key"].encode("UTF-8"),
        bcrypt.gensalt()).decode("UTF-8")

    db_session.commit()

    return jsonify(success=True)


@server.route("/users/", methods=["GET"])
@auth_required
def get_users(user):
    if not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "get users")

    users = []
    for u in User.query.all():
        users.append({
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
        })

    return jsonify(users=users)

@server.route("/users/", methods=["PUT"])
@auth_required
def add_user(user):
    if not user.admin:
        return error_response("not_admin", "You must be an administrator to add"
            " users")

    schema = {
        "type": "object",
        "properties": {
            "full_name": {"type": "string"},
            "username": {"type": "string"},
            "email": {"type": "string"},
            "public_key": {"type": "string"},
            "admin": {"type": "boolean"},
            "encrypted_private_key": {"type": "string"},
            "aes_iv": {"type": "string"},
            "pbkdf2_salt": {"type": "string"},
            "auth_key": {"type": "string"},
        },
        "required": ["full_name", "username", "email", "public_key", "admin",
            "encrypted_private_key", "aes_iv", "pbkdf2_salt", "auth_key"]
    }

    error = validate_schema(request.json, schema)
    if error:
        return error

    if User.query.filter(User.username==request.json["username"]).count():
        return error_response("already_exists", "A user with that username"
            " already exists!")

    u = User();
    u.full_name = request.json["full_name"]
    u.username = request.json["username"]
    u.email = request.json["email"]
    u.public_key = request.json["public_key"]
    u.admin = request.json["admin"]
    u.encrypted_private_key = request.json["encrypted_private_key"]
    u.aes_iv = request.json["aes_iv"]
    u.pbkdf2_salt = request.json["pbkdf2_salt"]
    u.auth_hash = bcrypt.hashpw(request.json["auth_key"].encode("UTF-8"),
        bcrypt.gensalt()).decode("UTF-8")

    db_session.add(u)
    db_session.commit()

    return jsonify(user_id=u.id)

@server.route("/folders/<folder_id>/public_keys/", methods=["GET"])
@auth_required
def folders_public_keys(user, folder_id):
    f = Folder.query.get(folder_id)
    if not f:
        return error_response("item_not_found", "Folder not found")

    if not f.user_can_write(user):
        return error_response("insufficient_permissions", "You do not have "
            "write permission for this folder")

    public_keys = []

    for p in f.permissions:
        public_keys.append({
            "user_id": p.user.id,
            "public_key": p.user.public_key
        })

    admins = User.query.filter(User.admin==True)
    for a in admins:
        public_keys.append({
            "user_id": a.id,
            "public_key": a.public_key
        })

    return jsonify(public_keys=public_keys)

# TODO: Change URL to be /folders/<folder_id>/accounts/ ????
@server.route("/accounts/add/", methods=["PUT"])
@auth_required
def accounts_add(user):
    schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "integer"},
            "encrypted_account_data": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "integer"},
                        "password": {"type": "string"},
                        "account_metadata": {"type": "string"},
                        "encrypted_aes_key": {"type": "string"},
                    },
                    "required": ["user_id", "password", "encrypted_aes_key",
                        "account_metadata"]
                }
            }
        },
        "required": ["folder_id", "encrypted_account_data"]
    }

    error = validate_schema(request.json, schema)

    folder_id = request.json["folder_id"]
    encrypted_account_data = request.json["encrypted_account_data"]

    f = Folder.query.get(folder_id)
    if not f:
        return error_response("item_not_found", "Folder not found")

    if not f.user_can_write(user):
        return error_response("insufficient_permissions", "You do not have "
            "write permission for this folder")

    a = Account(folder_id=folder_id)
    db_session.add(a)
    db_session.flush()

    for item in encrypted_account_data:
        db_session.add(AccountDataItem(
            user_id=item["user_id"],
            account_id=a.id,
            password=item["password"],
            account_metadata=item["account_metadata"],
            encrypted_aes_key=item["encrypted_aes_key"],
        ))

    db_session.commit()

    return jsonify(account_id=a.id)

@server.route("/accounts/<account_id>/", methods=["POST"])
@auth_required
def accounts_edit(user, account_id):
    schema = {
        "type": "object",
        "properties": {
            "encrypted_account_data": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "integer"},
                        "password": {"type": "string"},
                        "account_metadata": {"type": "string"},
                        "encrypted_aes_key": {"type": "string"},
                    },
                    "required": ["user_id", "password", "encrypted_aes_key",
                        "account_metadata"]
                }
            }
        },
        "required": ["encrypted_account_data"]
    }

    error = validate_schema(request.json, schema)

    encrypted_account_data = request.json["encrypted_account_data"]

    a = Account.query.get(account_id)

    if not a:
        return error_response("item_not_found", "Account could not be found")

    if not a.folder.user_can_write(user):
        return error_response("insufficient_permissions", "You do not have "
            "write permission for this folder")

    AccountDataItem.query.filter(AccountDataItem.account_id==a.id).delete()

    for item in encrypted_account_data:
        db_session.add(AccountDataItem(
            user_id=item["user_id"],
            account_id=a.id,
            password=item["password"],
            account_metadata=item["account_metadata"],
            encrypted_aes_key=item["encrypted_aes_key"],
        ))

    db_session.commit()

    return jsonify(success=True)

@server.route("/accounts/", methods=["POST"])
@auth_required
def accounts_batch_update(user):
    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "account_id": {"type": "integer"},
                "encrypted_account_data": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "user_id": {"type": "integer"},
                            "password": {"type": "string"},
                            "account_metadata": {"type": "string"},
                            "encrypted_aes_key": {"type": "string"},
                        },
                        "required": ["user_id", "password", "encrypted_aes_key",
                            "account_metadata"]
                    }
                }
            },
            "required": ["account_id", "encrypted_account_data"]
        }
    }

    error = validate_schema(request.json, schema)

    for account in request.json:
        encrypted_account_data = account["encrypted_account_data"]
        account_id = account["account_id"]

        a = Account.query.get(account_id)

        if not a:
            return error_response("item_not_found",
                "Account could not be found")

        if not a.folder.user_can_write(user):
            return error_response("insufficient_permissions", "You do not have "
                "write permission for this folder")

        for item in encrypted_account_data:
            AccountDataItem.query.filter(
                AccountDataItem.account_id == a.id).filter(
                AccountDataItem.user_id == item["user_id"]).delete()
            db_session.add(AccountDataItem(
                user_id=item["user_id"],
                account_id=a.id,
                password=item["password"],
                account_metadata=item["account_metadata"],
                encrypted_aes_key=item["encrypted_aes_key"],
            ))

    db_session.commit()

    return jsonify(success=True)

@server.route("/accounts/<account_id>/", methods=["DELETE"])
@auth_required
def accounts_delete(account_id, user):
    a = Account.query.get(account_id)
    if not a:
        return error_response("item_not_found", "Account not found")

    if not a.folder.user_can_write(user):
        return error_response("insufficient_permissions", "You do not have "
            "write permission for this folder")

    db_session.delete(a)
    db_session.commit()

    return jsonify(success=True)

@server.route("/folders/<folder_id>/accounts/", methods=["GET"])
@auth_required
def folder_get_accounts(user, folder_id):
    f = Folder.query.get(folder_id)
    if not f:
        return error_response("item_not_found", "Folder not found")

    if not f.user_can_read(user):
        return error_response("insufficient_permissions", "You do not have "
            "read permission for this folder")

    accounts = []
    for a in f.accounts:
        try:
            ad = AccountDataItem.query.filter(AccountDataItem.account_id==a.id
                ).filter(AccountDataItem.user_id==user.id).one()
        except (NoResultFound, MultipleResultsFound):
            return error_response("corrupt_account", "The account you are "
                "attempting to load appears to be corrupt, please ask your "
                "administrator to rebuild this folder")

        accounts.append({
            "account_metadata": ad.account_metadata,
            "encrypted_aes_key": ad.encrypted_aes_key,
            "id": a.id,
        })

    return jsonify(accounts=accounts)

@server.route("/folders/<folder_id>/permissions/", methods=["GET"])
@auth_required
def folder_get_permissions(user, folder_id):
    if not user.admin:
        return error_response("insufficient_permissions", "You must be an "
            "admin to view permissions for a folder")

    f = Folder.query.get(folder_id)
    if not f:
        return error_response("item_not_found", "Folder not found")

    permissions = []
    for p in f.permissions:
        permissions.append({
            "user_id": p.user.id,
            "read": p.read,
            "write": p.write,
        })

    return jsonify(permissions=permissions)

@server.route("/folders/<folder_id>/permissions/", methods=["POST"])
@auth_required
def folders_set_permissions(user, folder_id):
    if not user.admin:
        return error_response("not_admin", "You must be an administrator to "
            "edit the permissions on a folder")

    schema = {
        "type": "object",
        "properties": {
            "permissions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "integer"},
                        "read": {"type": "boolean"},
                        "write": {"type": "boolean"}
                    },
                    "required": ["user_id", "read", "write"]
                }
            }
        },
        "required": ["permissions"]
    }

    error = validate_schema(request.json, schema)
    if error:
        return error

    if not Folder.query.filter(Folder.id==folder_id).count():
        return error_response("item_not_found", "Folder not found")

    for permission in request.json.get("permissions"):
        user_id = permission.get("user_id")

        u = User.query.get(user_id)
        if not u:
            return error_response("item_not_found", "User with ID {} not found"
                "".format(user_id))

        if u.admin:
            return error_response("input_validation_fail", "Cannot set "
                "permissions for an administrator, administrators already have "
                "full access to all folders")

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

@server.route("/accounts/<account_id>/password/", methods=["GET"])
@auth_required
def accounts_get_password(user, account_id):
    a = Account.query.get(account_id)
    if not a:
        return error_response("item_not_found", "Account not found")

    if not a.folder.user_can_read(user):
        return error_response("insufficient_permissions", "You do not have read"
            " permission for this folder")

    try:
        ad = AccountDataItem.query.filter(AccountDataItem.account_id==a.id
            ).filter(AccountDataItem.user_id==user.id).one()
    except (NoResultFound, MultipleResultsFound):
        return error_response("corrupt_account", "The account you are "
            "attempting to load appears to be corrupt, please ask your "
            "administrator to rebuild this folder")

    return jsonify(password={
        "encrypted_password": ad.password,
        "encrypted_aes_key": ad.encrypted_aes_key,
    })

@server.route("/accounts/<account_id>/", methods=["GET"])
@auth_required
def get_account(user, account_id):
    a = Account.query.get(account_id)
    if not a:
        return error_response("item_not_found", "Account not found")

    if not a.folder.user_can_read(user):
        return error_response("insufficient_permissions", "You do not have "
            "read permission for the folder that this account belongs to")

    try:
        ad = AccountDataItem.query.filter(AccountDataItem.account_id==a.id
            ).filter(AccountDataItem.user_id==user.id).one()
    except (NoResultFound, MultipleResultsFound):
        return error_response("corrupt_account", "The account you are "
            "attempting to load appears to be corrupt, please ask your "
            "administrator to rebuild this folder")

    account = {
        "account_metadata": ad.account_metadata,
        "encrypted_aes_key": ad.encrypted_aes_key,
        "id": a.id,
    }

    return jsonify(account=account)

@server.route("/check_auth/", methods=["GET"])
@auth_required
def check_auth(user):
    return jsonify(success=True)
