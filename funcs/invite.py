from .Session import Session
from .Logger import Logger
import time

l = Logger("Invite.py","","")

class Invite:
    def __init__(code:str, db:"Database"):
        self.db = db
        self.code = code

        self.valid = self.__is_valid()

    def __is_valid(self):
        inviter = db.collection.find_one({f"invites.{self.code}":{"$exists":True}})
        if inviter is None: 

            l.log("Invite is invalid (inviter does not exist)")
            return False

        """ # invite format

        invites {
            code: {
                used: bool,
                expires: timestamp,
                used_by: user id (string)
            }
        }

        """

        invite = inviter.get("invites",{}).get(self.code)
        if invite.get("used"):
            l.log("Invite invalid (already used)")
            return False

        inviter_id = inviter.get("_id")
        if time.time() > invite.get("expires"):
            l.log("Invite invalid (expired)")
            return False
        
        # invite is guaranteed to be valid beyond this point


    def use(self, target_user:str):
        if not self.valid: 
            raise ValueError("Invite is not valid")

        self.db.collection.update_one(
            {"_id": inviter_id},
            {"$set": {
                f"invites.{code}.used": True,
                f"invites.{code}.used_by": target_user,
            }}
        )

        return True





    
    @staticmethod
    def create(session:Session) -> bool:
        pass