import requests
import time
import json
import nacl.utils
import nacl.signing
import nacl.encoding
import nacl.secret

from base64 import b64encode
from base64 import b64decode

class Pkid:
 
    def __init__(self, node_url, entropy):
        self.node_url = node_url
        self.node_version = "v1"
        self.signing_key = nacl.signing.SigningKey(entropy)
        self.verify_key = self.signing_key.verify_key
        self.verify_key_hex = bytes(self.verify_key).hex()
        self.secret_box = nacl.secret.SecretBox(entropy)
        self.data_version = 1

    def _get_headers(self): 
        authorization = json.dumps({"intent": "pkid.store", "timestamp": round(time.time() * 1000)})
        headers = {"Content-Type": "application/json", "Authorization": self._sign(authorization)}
        return headers
    
    def _sign(self, value):
        signed = self.signing_key.sign(value.encode())
        return b64encode(signed).decode("UTF-8")

    def _verify_sign(self, value):
        return self.verify_key.verify(value).decode("UTF-8")

    def _encrypt(self, value):
        return b64encode(self.secret_box.encrypt(value)).decode("UTF-8")

    def _decrypt(self, value):
        return self.secret_box.decrypt(value)

    def set_document(self, key, value, is_encrypted = False):
        headers = self._get_headers()
        handled_value = self._encrypt(value.encode("UTF-8")) if is_encrypted else value.encode("UTF-8")

        envelope = json.dumps({
            "is_encrypted": is_encrypted,
            "payload": handled_value,
            "data_version": self.data_version
        })

        signed_envelope = json.dumps(self._sign(envelope))
        destination = f"{self.node_url}/{self.node_version}/documents/{self.verify_key_hex}/{key}"

        response = requests.put(destination, headers = headers, data = signed_envelope)
        return json.loads(response.text)["message"]

    def get_document(self, key):
        headers = self._get_headers()
        destination = f"{self.node_url}/{self.node_version}/documents/{self.verify_key_hex}/{key}"

        response = requests.get(destination, headers = headers)

        signed_data = b64decode(response.json()["data"])
        data = json.loads(self._verify_sign(signed_data))

        handled_payload = self._decrypt(b64decode(data["payload"])).decode("UTF-8") if data["is_encrypted"] else data["payload"]

        return handled_payload