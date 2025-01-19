from typing import TypedDict, Dict
import logging
import time
from database.tables.users import Users
from database.tables.users import UserType, InviteType
from database.exceptions import UserNotExistError, InviteException
from security.encryption import Encryption

INVITE_LENGTH:int=16  

logger:logging.Logger = logging.getLogger("frii.site")

class Invites(Users):
    def __init__(self, mongo_client):
        super().__init__(mongo_client)

    def is_valid(self, code:str) -> bool:
        logger.info(f"Checking invite {code}")
        if len(code) != INVITE_LENGTH:
            return False
        
        invite_holder: UserType | None = self.find_user({f"invites.{code}": {"$exists":True}})

        if invite_holder is None:
            return False
        
        invite:InviteType | None = invite_holder.get("invites",{}).get(code)
        
        if invite is None:
            return False
        
        return not invite["used"]
        
    
    def create(self, user_id:str) -> str:
        """
        Creates an invitation code for a user.
        Args:
            user_id (str): The ID of the user for whom the invitation code is being created.
        Returns:
            str: The generated invitation code.
        Raises:
            UserNotExistError: If the user does not exist.
            InviteException: If the user has already made too many invites.
        """
        logger.info("Creating invite")
        invite_code:str = Encryption.generate_random_string(INVITE_LENGTH)
        
        user_data: UserType | None = self.find_user({"_id":user_id})
        
        if user_data is None:
            raise UserNotExistError("User does not exist!")
        
        user_invites: Dict[str,InviteType] = user_data.get("invites",{})
        
        if len(user_invites) >= 3:
            raise InviteException("User has made too many invites")
        
        self.modify_document(
            {"_id":user_id},
            "$set",
            f"invites.{invite_code}",
            {"used":False,"used_by":None,"used_at":None,"created":round(time.time())}
        )
        
        return invite_code
        
        
    def use(self, user_id:str, invite_code:str) -> bool:
        if not self.is_valid(invite_code):
            raise InviteException("Invite is not valid")

        self.table.update_one(
            {f"invites.{invite_code}":{"$exists":True}},
            {"$set":{
                f"invites.{invite_code}.used":True,
                f"invites.{invite_code}.used_by": user_id,
                f"invites.{invite_code}.used_at":round(time.time()),
                }
            }
        )

        return True