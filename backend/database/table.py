import os
from typing import Dict, List
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.cursor import Cursor
from pymongo.database import Database


class Table:
    def __init__(self, mongo_client:MongoClient, table_name:str) -> None:
        load_dotenv()
        self.cluster:MongoClient = mongo_client
        self.db:Database = self.cluster["database"]
        self.table:Collection = self.db[table_name]

    def find_item(self,filter:Dict[str,any]) -> str | int | float | dict | list | None:
        result:dict = self.table.find_one(filter) # Not simply returning the result in case we need to do something in the future
        return result

    def find_items(self,filter:Dict[str,any]) -> List[dict]:
        cursor:Cursor = self.table.find(filter) 
        return [item for item in cursor]
    
    def get_table(self) -> List[dict]:
        cursor:Cursor = self.table.find() 
        return [item for item in cursor]
        
    def insert_document(self,document:dict) -> None:
        self.table.insert_one(document)

    def modify_document(
            self, filter:Dict[str,any],
            operation:str,
            key:str,
            value:any, 
            create_if_not_exist:bool=False
    ) -> None:
        self.table.update_one(
            filter,
            {operation: {key:value}},
            upsert=create_if_not_exist
        ) 

    def create_index(self, key:str) -> None:
        self.table.create_index(key)

    def delete_in_time(self, date_key:str) -> None:
        self.table.create_index(date_key, expireAfterSeconds=1)

    def delete_document(self, filter:Dict[str,any]) -> None:
        self.table.delete_one(filter)

    def delete_many(self, filter:Dict[str,any]) -> None:
        self.table.delete_many(filter)

    def remove_key(self,filter:Dict[str,any], key:str) -> None:
        self.table.update_one(filter,{"$unset":{ key, "" }})

