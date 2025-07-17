from database.table import Table
from typing import Literal, TypedDict
import datetime
import time
import logging
from database.exceptions import FilterMatchError

logger = logging.getLogger("frii.site")


class NewSessionType(TypedDict):
    _id: str
    type: Literal["access", "refresh"]
    created: int
    expires: datetime.datetime
    agent: str
    ip: str


class AccessTokenType(NewSessionType):
    parent: str


class Sessions(Table):
    def __init__(self, mongo_client):
        super().__init__(mongo_client, "sessions")

    def add_session(
        self,
        uid: str,
        user_id: str,
        type: Literal["access", "refresh"],
        expires: int,
        user_agent: str,
        ip: str,
        parent: str | None = None,
    ) -> None:
        payload = {
            "_id": uid,
            "owner": user_id,
            "type": type,
            "created": round(time.time()),
            "expires": datetime.datetime.fromtimestamp(expires),
            "agent": user_agent,
            "ip": ip,
        }

        if parent:
            payload["parent"] = parent

        self.insert_document(payload)
        self.delete_in_time("expires")

    def get_session(self, uid: str) -> NewSessionType | AccessTokenType | dict | None:
        return self.find_item({"_id": uid})

    def delete_session_pair(self, refresh_uid: str) -> bool:
        """Deletes both the refresh and access token for said sesison"""
        logger.info("Marking session as disabled")

        if len(refresh_uid) < 30:
            logger.error(f"Small refresh token passed {len(refresh_uid)}")
            return False

        del_count = self.delete_many(
            {"$or": [{"_id": refresh_uid}, {"parent": refresh_uid}]}
        )

        if not del_count:
            logger.warning("Failed to delete session as there werent any matches")
            logger.debug(refresh_uid)
            return False

        logger.info(f"Deleted {del_count} sessions")
        return True
