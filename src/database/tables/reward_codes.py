from typing import Dict, List
from typing_extensions import NotRequired, TypedDict
import time
import logging
from pymongo import MongoClient
from database.tables.users import Users
from database.table import Table
from security.encryption import Encryption

logger: logging.Logger = logging.getLogger("frii.site")

RewardType = TypedDict(
    "RewardType",
    {
        "_id": str,
        "created": int,
        "mappings": dict,
        "associated-email": str,
        "email-hash": str,
        "used": bool,
        "used-by": None | str,
    },
)


class Rewards(Table):
    def __init__(self, mongo_client: MongoClient, users: Users):
        self.encryption: Encryption = users.encryption
        self.users: Users = users
        super().__init__(mongo_client, "rewards")

    def create(self, email: str, rewards: dict) -> str:
        """Creates a new reward code

        :param rewards: a mongodb mapping which specifies what properties to change. Eg: `{"$set": {"permissions.wildcards": True}}`
        :type rewards: dict
        """

        document: RewardType = {
            "_id": Encryption.generate_random_string(16),
            "created": round(time.time()),
            "mappings": rewards,
            "associated-email": self.encryption.encrypt(email),
            "email-hash": self.encryption.sha256(email + "supahcool"),
            "used": False,
            "used-by": None,
        }

        self.table.insert_one(document)

        return document["_id"]

    def use(self, user_id: str, code: str) -> bool:
        reward: RewardType | None = self.find_item({"_id": code})  # type: ignore[assignment]

        if reward is None:
            logger.warning("Code doesn't exist")
            return False

        if reward.get("used"):
            logger.warning("Code has already been used")
            return False

        self.users.table.update_one({"_id": user_id}, reward.get("mappings", {}))
        self.table.update_one(
            {"_id": code}, {"$set": {"used": True, "used-by": user_id}}
        )
        return True
