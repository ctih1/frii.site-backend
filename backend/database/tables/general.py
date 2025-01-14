import os
import time
from database.table import Table
from database.exceptions import (
    InviteException, EmailException, UsernameException
    )
from email.email import Email
from security.encryption import Encryption

class General(Table):
    def __init__(self, mongo_client, table_name):
        super().__init__(mongo_client, "frii.site")
        self.encryption:Encryption = Encryption(os.getenv("ENC_KEY"))

    def create_user(self,username: str, password: str,
                    email: str, language: str, country,
                    time_signed_up, email_instance:Email,
                    invite_code:str
                    ) -> None:
        original_username:str = username
        
        hashed_username:str = Encryption.sha256(username)
        hashed_password:str = Encryption.sha256(password)

        invite_user:dict = self.find_item({f"invites.{invite_code}":{"$exists":True}})

        if invite_user is None:
            raise InviteException("Invite is not valid")
        
        if invite_user["invites"][invite_code]["used"]:
            raise InviteException("Invite has already been used!")
        
        if email_instance.is_taken(email):
            raise EmailException("Email is already in use!")
        
        if self.find_item({"_id":hashed_username}) is not None:
            raise UsernameException("Username already taken!")
        
        account_data:dict = {
            "_id": hashed_username,
            "email": self.encryption.encrypt(email),
            "password": self.encryption.create_password(hashed_password),
            "display-name": self.encryption.encrypt(hashed_username),
            "username": self.encryption.encrypt(original_username),
            "lang": language,
            "country": country,
            "email-hash": Encryption.sha256(email+"supahcool"),
            "accessed-from": [],
            "created": time_signed_up,
            "last-login": time.time(),
            "permissions": {"max-domains":3, "invite":False},
            "feature-flags": {},
            "verified": False,
            "domains": {},
            "api-keys": {},
            "credits": 200,
            "invite-code": invite_code
        }

        self.table.update_one(
            {
                f"invites.{invite_code}":
                    {"$exists":True}
            },
            {
                "$set":{
                    f"invites.{invite_code}.used":True,
                    f"invites.{invite_code}.used_by": username,
                    f"invites.{invite_code}.used_at": round(time.time())
                    }
                }
        )

        self.insert_document(account_data)

        if not email_instance.send_code(username,email,original_username):
            raise EmailException("Email already in use!")
        

    