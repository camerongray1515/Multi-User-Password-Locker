import sys
import os
import argparse
import base64
import hashlib
import bcrypt
from models import db_session, create_all, init, User
from flask import Flask, jsonify, request
from getpass import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from pbkdf2 import PBKDF2

server = Flask(__name__)

connection_string = "sqlite:///test.sqlite"
key_length = 2048

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
def index():
    return jsonify([{"foo": "bar"}])

def initialise_db():
    print("Initialising database...", end="")
    sys.stdout.flush()
    init(connection_string)
    create_all()
    print("Done!")

def add_user():
    print("For better security it is recommended that you add users using a"
        " client on a different machine from the server, this utility is only"
        " designed for adding a user to an otherwise empty system.\n")
    init(connection_string)
    u = User()
    while not u.username:
        u.username = input("Enter username: ")
    while not u.full_name:
        u.full_name = input("Enter full name: ")
    while not u.email:
        u.email = input("Enter email: ")
    password = None
    while not password:
        password = getpass("Enter password: ")
    admin_response = None
    while admin_response not in ["y", "n"]:
        admin_response = input("Is user an admin? [y/n]: ")
    u.admin = admin_response == "y"

    print("Generating keys...", end="")
    sys.stdout.flush()

    private = RSA.generate(key_length)
    public = private.publickey()

    salt = os.urandom(8)
    key = PBKDF2(password, salt).read(32)
    iv = os.urandom(16)
    cypher = AES.new(key, AES.MODE_CFB, iv)

    encrypted_private_key = cypher.encrypt(private.exportKey())

    u.public_key = public.exportKey()
    u.encrypted_private_key = base64.b64encode(encrypted_private_key)
    u.pbkdf2_salt = base64.b64encode(salt)
    u.aes_iv = base64.b64encode(iv)

    auth_key = hashlib.sha512(
        "{}${}".format(u.username, password).encode("UTF-8")).hexdigest()

    u.auth_hash = bcrypt.hashpw(auth_key.encode("UTF-8"), bcrypt.gensalt())

    print("Done!")
    print("Adding user...", end="")
    sys.stdout.flush()
    db_session.add(u)
    db_session.commit()
    print("Done!")


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--run-server", action="store_true")
    group.add_argument("--initialise-db", action="store_true")
    group.add_argument("--add-user", action="store_true")
    args = parser.parse_args()

    if args.run_server:
        pass
    elif args.initialise_db:
        initialise_db()
    elif args.add_user:
        add_user()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
