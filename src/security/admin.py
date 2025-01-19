import os
from typing import TypedDict, List
from security.session import Session
from security.encryption import Encryption
from database.tables.users import Users
from database.tables.users import UserType
from database.tables.domains import DomainFormat
from database.exceptions import UserNotExistError

user_basic_data = TypedDict("user_basic_data", {
    "username":str,
    "email": str,
    "created": int,
    "last-login": int,
    "domains": dict
})

class Admin:
    def __init__(self, mongo_client):
        self.table:Users = Users(mongo_client)
        self.encryption:Encryption = Encryption(os.getenv("ENC_KEY"))
        
    @Session.requires_auth
    @Session.requires_permission("userdetails")
    def get_basic_data(self, session:Session, target_user:str) -> dict:
        user_data:UserType | None = self.table.find_user({"_id":target_user})

        if user_data is None:
            raise UserNotExistError()

        return {
            "username": self.encryption.decrypt(user_data["display-name"]),
            "email": self.encryption.decrypt(user_data["email"]),
            "created": user_data["created"],
            "last-login": user_data["last-login"],
            "domains": user_data["domains"],
            "permissions": user_data.get("permissions")
        }
    
    @Session.requires_auth
    @Session.requires_permission("userdetails")
    def get_emails(self, session:Session, filter:dict) -> List[str]:
        results:List[UserType] = self.table.find_users(filter) or []
        return [self.encryption.decrypt(user["email"]) for user in results]
    
    @Session.requires_auth
    @Session.requires_permission("userdetails")
    def get_email(self, session:Session, target_user:str) -> str:
        user_data: UserType | None = self.table.find_user({"_id":target_user})
        if user_data is None:
            raise UserNotExistError("User does not exist")
        return self.encryption.decrypt(user_data["email"])
    
    