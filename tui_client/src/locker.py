import requests
import json
import hashlib
import binascii
import os
import base64
from urllib.parse import urljoin
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

class RequestFailedError(Exception):
    def __init__(self, error_type, message):
        super(RequestFailedError, self).__init__(message)
        self.error_type = error_type

def base64_string(to_encode):
    return base64.b64encode(to_encode).decode("UTF-8")

class LockerEntity():
    def to_dict(self):
        raise NotImplementedError

    def __repr__(self):
        return "<class '{}': {}>".format(self.__class__.__name__, str(self.to_dict()))

class FolderPermission(LockerEntity):
    def __init__(self, user_id, read, write):
        self.user_id = int(user_id)
        self.read = bool(read)
        self.write = bool(write)

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "read": self.read,
            "write": self.write
        }

class Folder(LockerEntity):
    def __init__(self, name, folder_id=None):
        self.id = folder_id
        self.name = name

    def to_dict(self):
        return {"name": self.name, "id": self.id}

class User(LockerEntity):
    def __init__(self, id, full_name, username, email, auth_hash,
        encrypted_private_key, public_key, admin, pbkdf2_salt, aes_iv):
        self.id = id
        self.full_name = full_name
        self.username = username
        self.email = email
        self.auth_hash = auth_hash
        self.encrypted_private_key = encrypted_private_key
        self.public_key = public_key
        self.admin = admin
        self.pbkdf2_salt = pbkdf2_salt
        self.aes_iv = aes_iv

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "username": self.username,
            "email": self.email,
            "auth_hash": self.auth_hash,
            "encrypted_private_key": self.encrypted_private_key,
            "public_key": self.public_key,
            "admin": self.admin,
            "pbkdf2_salt": self.pbkdf2_salt,
            "aes_iv": self.aes_iv,
        }

class Account(LockerEntity):
    def __init__(self, name, username, password, notes):
        self.name = name
        self.username = username
        self.password = password
        self.notes = notes

    def to_dict(self):
        return {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "notes": self.notes,
        }

    def encrypt(self, public_key):
        iv = os.urandom(16)
        key = os.urandom(32)
        aes_cypher = AES.new(key, AES.MODE_CFB, iv)

        encrypted_password = aes_cypher.encrypt(self.password)
        encrypted_metadata = aes_cypher.encrypt(json.dumps({
            "name": self.name,
            "username": self.username,
            "notes": self.notes
        }))

        rsa_key = RSA.importKey(public_key)
        rsa_cypher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = rsa_cypher.encrypt(json.dumps({
            "key": base64_string(key),
            "iv": base64_string(key)
        }).encode("UTF-8"))

        return (
            base64_string(encrypted_aes_key),
            base64_string(encrypted_metadata),
            base64_string(encrypted_password)
        )


class Locker:
    def __init__(self, server, port, username, password):
        self.server = server
        self.port = port
        self.username = username
        self.auth_key = binascii.hexlify(hashlib.pbkdf2_hmac("sha512",
            password.encode("UTF-8"), username.encode("UTF-8"), 100000)).decode(
                "UTF-8")

    def _get_auth(self):
        auth = requests.auth.HTTPBasicAuth(self.username, self.auth_key)
        return auth

    def _get_url(self, endpoint):
        endpoint += "/"
        url = urljoin("http://{}:{}".format(self.server, self.port),
            endpoint)
        return url

    def _check_errors(self, r):
        if r.get("error"):
            raise RequestFailedError(r.get("error"), r.get("message"))
        return True

    def _folder_public_keys(self, folder_id):
        r = requests.get(self._get_url("folders/{}/public_keys/".format(
            folder_id)), auth=self._get_auth()).json()

        self._check_errors(r)

        return r["public_keys"]

    def get_folders(self):
        r = requests.get(self._get_url("folders"), auth=self._get_auth()).json()

        folders = []

        for f in r["folders"]:
            folders.append(Folder(f["name"], f["id"]))

        return folders

    def add_folder(self, folder):
        r = requests.put(self._get_url("folders/add"), json=folder.to_dict(),
            auth=self._get_auth()).json()

        self._check_errors(r)

        folder.id = r.get("folder_id")

        return folder

    def set_folder_permissions(self, folder_id, permissions):
        if type(permissions) == FolderPermission:
            permissions = [permissions]

        permission_dicts = []
        for p in permissions:
            permission_dicts.append(p.to_dict())

        r = requests.post(self._get_url("folders/set_permissions"),
            json={"folder_id": folder_id, "permissions": permission_dicts},
            auth=self._get_auth()).json()

        self._check_errors(r)

        return True

    def delete_folder(self, folder_id):
        r = requests.delete(
            self._get_url("folders/delete/{}".format(folder_id)),
            auth=self._get_auth()).json()

        self._check_errors(r)

        return True

    def get_user(self, user_id=None):
        url = self._get_url("users" + (
            "/{}".format(user_id) if user_id else ""))

        r = requests.get(url, auth=self._get_auth()).json()

        self._check_errors(r)

        u = r["user"]

        user = User(u["id"], u["full_name"], u["username"], u["email"],
            u["auth_hash"], u["encrypted_private_key"], u["public_key"],
            u["admin"], u["pbkdf2_salt"], u["aes_iv"])

        return user

if __name__ == "__main__":
    l = Locker("127.0.0.1", 5000, "camerongray", "password")
    try:
        # p = FolderPermission(user_id=2, read=True, write=False)
        # l.set_folder_permissions(1, p)
        # print(l.add_folder(Folder("Second test folder")).to_dict())
        # print(l.get_user())
        key = l._folder_public_keys(1)[0]["public_key"]

        a = Account("Test Account", "camerongray", "secretpass", "Butts")
        print(a.encrypt(key))

    except RequestFailedError as ex:
        print(ex.error_type)
        print(str(ex))
    print(l.get_folders())
