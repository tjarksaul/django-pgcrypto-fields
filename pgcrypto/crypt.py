import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .constants import SALT


class Cryptographer(object):

    @classmethod
    def fernet_generator(cls, password):
        return Fernet(base64.urlsafe_b64encode(PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100000,
            backend=default_backend()
        ).derive(password)))

    @classmethod
    def encrypted(cls, password, content):
        return cls.fernet_generator(password).encrypt(content)

    @classmethod
    def decrypted(cls, password, content):
        return cls.fernet_generator(password).decrypt(content)
