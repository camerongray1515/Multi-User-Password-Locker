from models import db_session, create_all, init, User
from flask import Flask, jsonify, request
from decorators import auth_required

server = Flask(__name__)

# Methods required:
#   - Get all public keys for an account, only for users who can edit
#   - Update encrypted aes key for an account, only for users who can edit
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
def index():
    return jsonify([{"foo": "bar"}])
