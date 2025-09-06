import random
import string
from hashlib import sha256
import bcrypt
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger("frii.site")


class Encryption:
    def __init__(self, encryption_key: str):
        self.fernet = Fernet(bytes(encryption_key, "utf-8"))

    @staticmethod
    def sha256(input: str) -> str:
        return sha256(input.encode("utf-8")).hexdigest()

    @staticmethod
    def create_password(plain_password: str) -> str:
        return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode(
            encoding="utf-8"
        )

    @staticmethod
    def check_password(password: str, encrypted_password: str) -> bool:
        return bcrypt.checkpw(
            password.encode("utf-8"), encrypted_password.encode("utf-8")
        )

    @staticmethod
    def generate_random_string(length: int) -> str:
        return "".join(
            random.SystemRandom().choice(string.ascii_letters + string.digits)
            for _ in range(length)
        )

    def encrypt(self, plain_data: str) -> str:
        return self.fernet.encrypt(bytes(plain_data, "utf-8")).decode(encoding="utf-8")

    def decrypt(self, encrypted_data: str) -> str:
        return self.fernet.decrypt(encrypted_data.encode("utf-8")).decode("utf-8")
