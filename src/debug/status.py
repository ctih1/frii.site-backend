from typing_extensions import NotRequired, TypedDict
from pymongo import MongoClient
from database.table import Table


StatusType = TypedDict("StatusType", {
    "issues":bool,
    "message": NotRequired[str]
})


class Status(Table):
    def __init__(self, mongo_client: MongoClient):
        super().__init__(mongo_client, "status")
    
    def get(self) -> StatusType:
        status_data: dict | None  = self.find_item({"_id":"current"})
        if status_data is None:
            return {"issues":False}
        return {
            "issues":True,
            "message": status_data.get(
                "message","We are experiencing server issues."
            )
        }
