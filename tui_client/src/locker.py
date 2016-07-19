import requests
import json
import hashlib
import binascii
import os
import base64
from urllib.parse import urljoin
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from pbkdf2 import PBKDF2

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
        encrypted_private_key, public_key, admin, pbkdf2_salt, aes_iv,
        private_key=None):
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
        self.private_key = private_key

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
            "private_key": self.private_key,
        }

class Account(LockerEntity):
    def __init__(self, name, username, password, notes, id=None):
        self.name = name
        self.username = username
        self.password = password
        self.notes = notes
        self.id = id

    def to_dict(self):
        return {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "notes": self.notes,
            "id": self.id
        }

    def get_encrypted(self, public_key):
        iv = os.urandom(16)
        key = os.urandom(32)
        encrypted_password = AES.new(key, AES.MODE_CFB, iv).encrypt(
            self.password)
        encrypted_metadata = AES.new(key, AES.MODE_CFB, iv).encrypt(json.dumps({
            "name": self.name,
            "username": self.username,
            "notes": self.notes
        }))

        rsa_key = RSA.importKey(public_key)
        rsa_cypher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = rsa_cypher.encrypt(json.dumps({
            "key": base64_string(key),
            "iv": base64_string(iv)
        }).encode("UTF-8"))

        return {
            "encrypted_aes_key": base64_string(encrypted_aes_key),
            "encrypted_metadata": base64_string(encrypted_metadata),
            "encrypted_password": base64_string(encrypted_password)
        }


class Locker:
    def __init__(self, server, port, username, password):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.auth_key = base64.b64encode(hashlib.pbkdf2_hmac("sha512",
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

    def check_auth(self):
        r = requests.get(self._get_url("check_auth"), auth=self._get_auth())

        return r.status_code != 401

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

    def get_current_user(self):
        url = self._get_url("users/self")

        r = requests.get(url, auth=self._get_auth()).json()

        self._check_errors(r)

        u = r["user"]

        pbkdf2_salt = base64.b64decode(u["pbkdf2_salt"])
        aes_iv = base64.b64decode(u["aes_iv"])
        encrypted_private_key = base64.b64decode(u["encrypted_private_key"])

        key = PBKDF2(self.password, pbkdf2_salt).read(32)
        cypher = AES.new(key, AES.MODE_CFB, aes_iv)
        private_key = cypher.decrypt(encrypted_private_key)

        user = User(
            u["id"],
            u["full_name"],
            u["username"],
            u["email"],
            u["auth_hash"],
            encrypted_private_key,
            base64.b64decode(u["public_key"]),
            u["admin"],
            pbkdf2_salt,
            aes_iv,
            private_key,
        )

        return user

    def add_account(self, folder_id, account):
        public_keys = self._folder_public_keys(folder_id)

        encrypted_account_data = []

        for pk in public_keys:
            encrypted = account.get_encrypted(base64.b64decode(pk["public_key"]))
            encrypted_account_data.append({
                "encrypted_aes_key": encrypted["encrypted_aes_key"],
                "account_metadata": encrypted["encrypted_metadata"],
                "password": encrypted["encrypted_password"],
                "user_id": pk["user_id"]
            })

        data = {
            "folder_id": folder_id,
            "encrypted_account_data": encrypted_account_data
        }

        r = requests.put(self._get_url("accounts/add"), json=data,
            auth=self._get_auth()).json()

        self._check_errors(r)

        return r["account_id"]

    def get_folder_accounts(self, folder_id, private_key):

        r = requests.get(self._get_url("folders/{}/accounts/".format(
            folder_id)), auth=self._get_auth()).json()

        self._check_errors(r)

        rsa_key = RSA.importKey(private_key)
        rsa_cypher = PKCS1_OAEP.new(rsa_key)

        accounts = []
        for a in r["accounts"]:
            metadata = json.loads(
                self._decrypt_account_data(private_key, a["encrypted_aes_key"],
                    a["account_metadata"]))
            accounts.append(Account(
                name=metadata["name"],
                username=metadata["username"],
                notes=metadata["notes"],
                id=a["id"],
                password=None,
            ))

        return accounts

    def get_account_password(self, account_id, private_key):
        r = requests.get(self._get_url("accounts/{}/password/".format(
            account_id)), auth=self._get_auth()).json()

        self._check_errors(r)

        password = self._decrypt_account_data(private_key,
            r["password"]["encrypted_aes_key"],
            r["password"]["encrypted_password"])

        return password

    def _decrypt_account_data(self, private_key, encrypted_aes_key, data):
        rsa_key = RSA.importKey(private_key)
        rsa_cypher = PKCS1_OAEP.new(rsa_key)

        aes_key = json.loads(rsa_cypher.decrypt(base64.b64decode(
            encrypted_aes_key)).decode("UTF-8"))
        print(base64.b64encode(aes_key).decode("UTF-8"))
        aes_cypher = AES.new(base64.b64decode(aes_key["key"]), AES.MODE_CFB,
            base64.b64decode(aes_key["iv"]))

        return aes_cypher.decrypt(base64.b64decode(data)).decode("UTF-8")

if __name__ == "__main__":
    l = Locker("127.0.0.1", 5000, "camerongray", "password")
    try:
        # p = FolderPermission(user_id=1, read=True, write=True)
        # l.set_folder_permissions(2, p)
        # print(l.add_folder(Folder("Second test folder")).to_dict())
        # print(l.get_user())

        # a = Account("Second Folder Account", "camerongray", "anotherpass", "Butts")
        # print(l.add_account(2, a))


        u = l.get_current_user()
        # print(l.get_folder_accounts(1, u.private_key))
        print(l.get_account_password(3, u.private_key))

    except RequestFailedError as ex:
        print(ex.error_type)
        print(str(ex))
    print(l.get_folders())
