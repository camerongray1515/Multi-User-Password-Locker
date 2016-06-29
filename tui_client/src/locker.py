import requests
import json
import hashlib
import binascii
from urllib.parse import urljoin

class RequestFailedError(Exception):
    def __init__(self, error_type, message):
        super(RequestFailedError, self).__init__(message)
        self.error_type = error_type

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
        # p = FolderPermission(user_id=1, read=True, write=True)
        # l.set_folder_permissions(1, p)
        # print(l.add_folder(Folder("Second test folder")).to_dict())
        print(l.get_user())
    except RequestFailedError as ex:
        print(ex.error_type)
        print(str(ex))
    print(l.get_folders())
