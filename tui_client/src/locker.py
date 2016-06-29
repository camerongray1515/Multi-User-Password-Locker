import requests
import json
import hashlib
import binascii
from urllib.parse import urljoin

class RequestFailedError(Exception):
    def __init__(self, error_type, message):
        super(RequestFailedError, self).__init__(message)
        self.error_type = error_type

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
        return r["folders"]

    def add_folder(self, name):
        r = requests.put(self._get_url("folders/add"), json={"name": name},
            auth=self._get_auth()).json()

        self._check_errors(r)

        return r.get("folder_id")

    def delete_folder(self, folder_id):
        r = requests.delete(
            self._get_url("folders/delete/{}".format(folder_id)),
            auth=self._get_auth()).json()

        self._check_errors(r)

        return True

if __name__ == "__main__":
    l = Locker("127.0.0.1", 5000, "camerongray", "password")
    try:
        print(l.delete_folder(2))
    except RequestFailedError as ex:
        print(ex.error_type)
        print(str(ex))
    print(l.get_folders())
