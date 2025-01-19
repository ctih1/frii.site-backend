import os
import time
from typing import List, Dict, TYPE_CHECKING
from typing_extensions import NotRequired, Required, TypedDict
from pymongo import MongoClient
from database.table import Table
import datetime

from database.exceptions import (
    InviteException, EmailException,
    UsernameException, UserNotExistError
)

from mail.email import Email
from security.encryption import Encryption
from security.session import SessionType

if TYPE_CHECKING:
    from database.tables.domains import DomainFormat
    from database.tables.sessions import Sessions as SessionTable


class CountryType(TypedDict):
    ip:str
    hostname:str
    city: str
    region: str
    country: str # 2 char country code (ex. FI)
    loc: str # latitude,longtitude
    org: str
    postal: str # Zip code
    timezone: str # TZ format (ex. Europe/Helsinki)
    country_name: str
    isEU: bool
    country_flag_url: str
    country_flag: dict # contains keys "emoji", and "unicode", which you can probably guess what it does
    country_currency: dict # contains keys "code", (ex. EUR), and symbol (ex. €)
    continent: dict # contains keys "code", (ex. EU), and name, (ex. Europe)
    latitude: str
    longitude: str

class InviteType(TypedDict):
    used:bool
    used_by:NotRequired[str]
    used_at: NotRequired[int] # epoch timestamp

UserPageType = TypedDict("UserPageType", {
    "username":str,
    "email":str,
    "lang": str,
    "country":CountryType,
    "created":int,
    "verified":bool,
    "permissions":Dict[str,bool],
    "beta-enroll":bool,
    "sessions": List[SessionType],
    "invites": Dict[str,InviteType]
})

UserType = TypedDict("UserType", {
    "_id": str,
    "email": str,
    "password":str,
    "display-name":str,
    "username": NotRequired[str],
    "lang": str,
    "country": CountryType,
    "email-hash": NotRequired[str],
    "accessed-from": NotRequired[List[str]],
    "created": int, # Epoch timestamp
    "last-login": int, # Epoch timestamp 
    "permissions": dict,
    "verified": bool,
    "domains": Required[Dict[str,'DomainFormat']],
    "feature-flags": NotRequired[Dict[str,bool]],
    "api-keys": NotRequired[Dict],
    "credits": NotRequired[int],
    "beta-enroll": NotRequired[bool],
    "beta-updated": NotRequired[int],
    "invites": NotRequired[Dict[str,Dict]],
    "invite-code": NotRequired[str]
})


class Users(Table):
    def __init__(self, mongo_client: MongoClient) -> str:
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

        invite_user:UserType = self.find_item({f"invites.{invite_code}":{"$exists":True}})

        if invite_user is None:
            raise InviteException("Invite is not valid")
        
        if invite_user["invites"][invite_code]["used"]:
            raise InviteException("Invite has already been used!")
        
        if email_instance.is_taken(email):
            raise EmailException("Email is already in use!")
        
        if self.find_item({"_id":hashed_username}) is not None:
            raise UsernameException("Username already taken!")
        
        account_data:UserType = {
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
            "last-login": round(time.time()),
            "permissions": {"max-domains":3, "invite":False},
            "feature-flags": {},
            "verified": False,
            "domains": {},
            "api-keys": {},
            "credits": 200,
            "invite-code": invite_code
        }

        self.insert_document(account_data)
        if not email_instance.send_verification_code(username,email):
            raise EmailException("Email already in use!")
        
        return hashed_username


    def create_invite(self,user_id:str) -> str:
        invite_code:str = Encryption.generate_random_string(16)
        invite_user:UserType = self.find_item({"_id":user_id})

        if len(invite_user.get("invites",{})) >= 3:
            raise InviteException("Invite limit exceeded")
        
        self.table.update_one(
            {"_id":user_id},
            {"$set": {
                    f"invites.{invite_code}":{
                        "used":False, "used_by":None,
                        "used_at":None, "created": round(time.time())
                    }
                }
            }
        )

        return invite_code
    

    def get_invites(self, user_id:str) -> Dict[str,InviteType] | dict:
        """Get user's invites.
        Returns empty dict if no invites are found
        Raises ValueError if user does not exist
        """
        user_data: UserType | None = self.find_item({"_id":user_id})

        if user_data is None:
            raise UserNotExistError("Invalid user!")
        
        return user_data.get("invites",{})
    

    def get_user_gdpr(self, user_id:str) -> dict:
        user_data:UserType | None = self.find_item({"_id":user_id})

        if user_data is None:
            raise UserNotExistError("Invalid user")
    
        return {
            "user_id": user_data["_id"],
            "location": user_data["country"],
            "creation_date": user_data["created"],
            "domains": user_data["domains"],
            "lang": user_data["lang"],
            "last_login": user_data["last-login"],
            "permissions": user_data["permissions"],
            "verified": user_data["verified"]
            }
    
    
    def get_user_profile(self, user_id:str, session_table: 'SessionTable') -> UserPageType:
        user_data: UserType | None = self.find_item({"_id":user_id})

        if user_data is None:
            raise UserNotExistError("Invalid user")
        
        return {
            "username": self.encryption.decrypt(user_data["display-name"]),
            "email": self.encryption.decrypt(user_data["email"]),
            "lang": user_data["lang"],
            "country": user_data["country"],
            "created": user_data["created"],    
            "verified": user_data["verified"],
            "permissions": user_data.get("permissions",{}),
            "beta-enroll": user_data.get("beta-enroll",False),
            "sessions": [{k:(round(v.timestamp()) if isinstance(v,datetime.datetime) else v) for k,v in session.items()} for session in session_table.find_items({"owner-hash": Encryption.sha256(user_id+"frii.site")})], # conversts datetime object of expire date in db to linux epoch int. fastapi's json encoder doesnt like datetime objects
            "invites": user_data.get("invites",{})  
        }

    def change_beta_enrollment(self, user_id:str, mode:bool=False) -> None:
        self.modify_document({"_id":user_id},"$set","beta-enroll",mode)
        self.modify_document({"_id":user_id},"$set","beta-updated",round(time.time()))

