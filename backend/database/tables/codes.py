import os
from typing import TypedDict
import time
import datetime
from database.table import Table
from security.encryption import Encryption
from security.session import Session

EXPIRE_TIME = 45*60

class Codes(Table):
    def __init__(self, mongo_client):
        super().__init__(mongo_client, "codes")

        self.verification_codes = {}
        self.recovery_codes = {}
        self.delete_codes = {}

        self.__sync_codes()

        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY"))

    def __sync_codes(self):
        codes = self.get_table()
        for code in codes:
            if code["type"] == "verification":
                self.verification_codes[code["_id"]] ["account"] = self.encryption.decrypt(code["account"])
                self.verification_codes[code["_id"]] ["expire"] = code["expire"]
            if code["type"] == "delete":
                self.delete_codes[code["_id"]] ["auth-token"] = self.encryption.decrypt(code["auth-token"])
                self.delete_codes[code["_id"]] ["expire"] = code["expire"]
            if code["type"] == "recovery":
                self.recovery_codes[code["_id"]] ["account"] = self.encryption.decrypt(code["account"])
                self.recovery_codes[code["_id"]] ["expire"] = code["expire"]
    
    def create_code(self, type:str, target_username:str=None, target_session:Session=None) -> str:
        code:str = Encryption.generate_random_string(16)
        if type == "verification":
            if target_username is None:
                raise ValueError("target_username must be specified for verification codes")
            self.verification_codes[code] = {
                "account": target_session,
                "expire": time.time() + EXPIRE_TIME
                }

            self.insert_document({
                "_id": code,
                "type":"verification",
                "expire": self.verification_codes[code]["expire"],
                "account": self.verification_codes[code]["account"],
                "expiresAfter": datetime.datetime.now() + datetime.timedelta(seconds=EXPIRE_TIME)
            })
        elif type == "delete":
            raise NotImplementedError()
        
        elif type == "recover":
            if target_username is None:
                raise ValueError("target_username must be specified for recovery")
            self.recovery_codes[code] = {
                "account": target_session,
                "expire": time.time() + EXPIRE_TIME
            }

            self.insert_document({
                "_id": code,
                "type":"recovery",
                "expire": self.verification_codes[code]["expire"],
                "account": self.verification_codes[code]["account"],
                "expiresAfter": datetime.datetime.now() + datetime.timedelta(seconds=EXPIRE_TIME)
            })
        else:
            raise ValueError("Code type is not valid")
        
        self.delete_in_time("expiresAfter")
        
        return code
