import logging
from typing import Dict, List, Any, Mapping
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.cursor import Cursor
from pymongo.database import Database
from database.exceptions import FilterMatchError

logger: logging.Logger = logging.getLogger("frii.site")


class Table:
    def __init__(self, mongo_client: MongoClient, table_name: str) -> None:
        logger.info(f"Initializing table {table_name}")
        self.name: str = table_name
        self.cluster: MongoClient = mongo_client
        self.db: Database = self.cluster["database"]
        self.table: Collection = self.db[table_name]

    def find_item(self, filter: Dict[str, Any]) -> dict | None:
        result: dict | None = self.table.find_one(
            filter
        )  # Not simply returning the result in case we need to do something in the future
        return result

    def find_items(self, filter: Dict[str, Any]) -> List[dict]:
        cursor: Cursor = self.table.find(filter)
        return [item for item in cursor]

    def get_table(self) -> List[dict]:
        cursor: Cursor = self.table.find()
        return [item for item in cursor]

    def insert_document(self, document: Mapping[Any, Any]) -> None:
        self.table.insert_one(document)

    def modify_document(
        self,
        filter: Dict[str, Any],
        operation: str,
        key: str,
        value: Any,
        create_if_not_exist: bool = False,
        ignore_no_matches: bool = False,
    ) -> None:
        result = self.table.update_one(
            filter, {operation: {key: value}}, upsert=create_if_not_exist
        )

        if result.matched_count == 0 and not ignore_no_matches:
            logger.error(
                f"Filter {filter} for table {self.name} couldn't match a document"
            )
            raise FilterMatchError("Filter didn't match anything")

    def create_index(self, key: str) -> None:
        logger.info(f"Creating index on table {self.name} for key {key}")
        self.table.create_index(key)

    def delete_in_time(self, date_key: str) -> None:
        logger.info(f"Creating delete index for key {date_key} on table {self.name}")
        self.table.create_index(date_key, expireAfterSeconds=1)

    def delete_document(self, filter: Dict[str, Any]) -> None:
        logger.info(f"Deleting document with filter {filter} on table {self.name}")
        self.table.delete_one(filter)

    def delete_many(self, filter: Dict[str, Any]) -> None:
        logger.info(f"Deleting many with filter {filter} on table {self.name}")
        self.table.delete_many(filter)

    def remove_key(self, filter: Dict[str, Any], key: str) -> bool:
        updateResult = self.table.update_one(filter, {"$unset": {key: ""}})
        print(updateResult.matched_count != 0)
        return updateResult.matched_count != 0
