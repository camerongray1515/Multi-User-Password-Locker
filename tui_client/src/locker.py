import requests
import json
import hashlib
import binascii
from urllib.parse import urljoin

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

    def get_folders(self):
        r = requests.get(self._get_url("folders"), auth=self._get_auth())
        return r.json()

if __name__ == "__main__":
    l = Locker("127.0.0.1", 5000, "camerongray", "password")
    print(l.get_folders())
