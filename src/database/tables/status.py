from typing import Dict, List
from typing_extensions import NotRequired, TypedDict
import time
import logging
from pymongo import MongoClient
from database.table import Table
from security.encryption import Encryption
from typing import TypedDict

logger: logging.Logger = logging.getLogger("frii.site")


class StatusType(TypedDict):
    _id: str
    time: float
    message: str
    active: bool


class Status(Table):
    def __init__(self, mongo_client: MongoClient):
        super().__init__(mongo_client, "Status")

    def get(self) -> StatusType:
        return self.find_item({"active": True})

    def set(self, message: str):
        self.modify_document({"active": True}, "$set", "active", False, False, True)
        self.insert_document(
            {
                "_id": Encryption.generate_random_string(16),
                "time": time.time(),
                "message": message,
                "active": True,
            }
        )
