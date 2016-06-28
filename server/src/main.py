import sys
import os
import argparse
import base64
import hashlib
import bcrypt
import binascii
from models import db_session, create_all, init, User
from getpass import getpass
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from pbkdf2 import PBKDF2
from config import get_config
from server import server

config = get_config()

def initialise_db():
    print("Initialising database...", end="")
    sys.stdout.flush()
    init(config["connection_string"])
    create_all()
    print("Done!")

def add_user():
    print("For better security it is recommended that you add users using a"
        " client on a different machine from the server, this utility is only"
        " designed for adding a user to an otherwise empty system.\n")
    init(config["connection_string"])
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

    private = RSA.generate(config["key_length"])
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

    auth_key = binascii.hexlify(hashlib.pbkdf2_hmac("sha512",
        password.encode("UTF-8"), u.username.encode("UTF-8"), 100000))

    u.auth_hash = bcrypt.hashpw(auth_key, bcrypt.gensalt())

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
        init(config["connection_string"])
        server.run(debug=True)
    elif args.initialise_db:
        initialise_db()
    elif args.add_user:
        add_user()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
