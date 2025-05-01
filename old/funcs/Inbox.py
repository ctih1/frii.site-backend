from .Database import Database
from .Token import Token
from .Utils import generate_random_string
from .Logger import Logger
from enum import Enum

class Importance(Enum):
    DANGER="danger"
    IMPORTANT="important"
    MESSAGE="message"



class Inbox:
    def __init__(self,db:Database):
        self.l = Logger("Inbox.py","None","None")
        self.db = db

    def get(self,user:Token) -> list:
        self.l.info(f"Getting inbox of user {user.username}")
        return self.db.get_data(user).get("inbox",[])

    def send(self,author:Token,target:str, title:str, desc:str,type:Importance) -> bool:
        """
        Sends am essage to a target. Note: target must be sha256 username
        """
        if(not self.db.get_data(author).get("permissions",{}).get("inbox",False)):
            self.l.permission(f"User {author.username} doesn't have permissions to send messages!")
            raise PermissionError

        message = {
            "_id": generate_random_string(16),
            "title":title,
            "description":desc,
            "type": type.value
        }
        self.db.collection.update_one(
            {"_id": target},
            {"$push": {"inbox":message}}
        )
        self.l.info(f"Sent message to user {target}")
        return False
