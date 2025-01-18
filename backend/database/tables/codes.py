from typing import TypedDict, Dict
from typing_extensions import NotRequired
import os
import time
import datetime
from pymongo import MongoClient
from database.table import Table
from security.encryption import Encryption
from security.session import Session


EXPIRE_TIME = 45*60

class GenericCodeFormat(TypedDict):
    account:str
    expire:int

class CodeStatus(TypedDict):
    valid:bool
    account: NotRequired[str]


class Codes(Table):
    def __init__(self, mongo_client:MongoClient):
        super().__init__(mongo_client, "codes")

        self.verification_codes:Dict[str,GenericCodeFormat] = {}
        self.recovery_codes:Dict[str,GenericCodeFormat] = {}
        self.deletion_codes:Dict[str,GenericCodeFormat] = {}

        self.encryption: Encryption = Encryption(os.getenv("ENC_KEY"))

        self.__sync_codes()


    def __sync_codes(self):
        codes = self.get_table()
        for code in codes:
            if code["type"] == "verification":
                self.verification_codes[code["_id"]] = {}
                self.verification_codes[code["_id"]]["account"] = self.encryption.decrypt(code["account"])
                self.verification_codes[code["_id"]]["expire"] = code["expire"]
            if code["type"] == "deletion":
                self.deletion_codes[code["_id"]] = {}
                self.deletion_codes[code["_id"]]["account"] = self.encryption.decrypt(code["account"])
                self.deletion_codes[code["_id"]]["expire"] = code["expire"]
            if code["type"] == "recovery":
                self.recovery_codes[code["_id"]] = {}
                self.recovery_codes[code["_id"]]["account"] = self.encryption.decrypt(code["account"])
                self.recovery_codes[code["_id"]]["expire"] = code["expire"]
    
    def create_code(self, type:str, target_username:str|None=None, target_session:Session=None) -> str:
        code:str = Encryption.generate_random_string(16)

        local_code:dict = {}

        if type == "verification":
            if target_username is None:
                raise ValueError("target_username must be specified for verification codes")
            
            self.verification_codes[code] = {
                "account": self.encryption.encrypt(target_username),
                "expire": round(time.time()) + EXPIRE_TIME
                }
            local_code = self.verification_codes

        elif type == "deletion":
            if target_username is None:
                raise ValueError("target_username must be specified for recovery")
            
            self.deletion_codes[code] = {
                "account": self.encryption.encrypt(target_username),
                "expire": round(time.time()) + EXPIRE_TIME
            }
            local_code = self.deletion_codes
        
        elif type == "recover":
            if target_username is None:
                raise ValueError("target_username must be specified for recovery")
            
            self.recovery_codes[code] = {
                "account": target_session,
                "expire": round(time.time()) + EXPIRE_TIME
            }
            local_code = self.recovery_codes

        else:
            raise ValueError("Code type is not valid")
        
        
        self.insert_document({
            "_id": code,
            "type":type,
            "expire": local_code[code]["expire"],
            "account": local_code[code]["account"],
            "expiresAfter": datetime.datetime.now() + datetime.timedelta(seconds=EXPIRE_TIME)
        })
        
        self.delete_in_time("expiresAfter")
        
        return code
    
    def is_valid(self, code:str, type:str) -> CodeStatus:
        if type == "verification":
            code_result = self.verification_codes.get(code)
        
        elif type == "deletion":
            code_result = self.deletion_codes.get(code)

        elif type == "recovery":
            code_result = self.deletion_codes.get(code)

        if code_result is None:
            return {"valid":False}
        
        if code_result["expire"] < round(time.time()):
            return {"valid":False} 
        
        return {"valid":True, "account":code_result["account"]}
    
    def delete_code(self, code:str, type:str):
        if type == "verification":
            try:
                del self.verification_codes[code]
            except Exception:
                pass
        self.table.delete_one({"_id":code})
