from typing import TypedDict, Dict, List
from typing_extensions import NotRequired
import time
import logging
from pymongo import MongoClient
from database.table import Table


logger:logging.Logger = logging.getLogger("frii.site")

class Blogs(Table):
    def __init__(self, mongo_client:MongoClient):
        super().__init__(mongo_client, "blog")

    def create(self, title:str, body:str):
        url = title.lower().replace(" ","-")
        self.insert_document({
            "_id": url[:24],
            "date": round(time.time()),
            "title": title,
            "body": body
        })
