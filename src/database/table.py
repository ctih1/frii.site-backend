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
        """Finds and item from the database

        :param filter: Filter. [More info here](https://www.mongodb.com/docs/compass/query/filter/)
        :type filter: Dict[str, Any]
        :return: the item found, None if the item isnt found
        :rtype: dict | None
        """
        result: dict | None = self.table.find_one(
            filter
        )  # Not simply returning the result in case we need to do something in the future
        return result

    def find_items(self, filter: Dict[str, Any]) -> List[dict]:
        """Finds multiple items from the database

        :param filter: Filter. [More info here](https://www.mongodb.com/docs/compass/query/filter/)
        :type filter: Dict[str, Any]
        :return: list of items found. returns an empty list if None is found
        :rtype: List[dict]
        """
        cursor: Cursor = self.table.find(filter)
        return [item for item in cursor]

    def get_table(self) -> List[dict]:
        """Gets every item inside a specific table.

        :return: a list of every document inside the collection
        :rtype: List[dict]
        """
        cursor: Cursor = self.table.find()
        return [item for item in cursor]

    def insert_document(self, document: Mapping[Any, Any]) -> None:
        """Creates a new document in the database

        :param document: the document
        :type document: Mapping[Any, Any]
        """
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
        """Modifies an item in the database

        :param filter: a filter for the document that will be modified
        :type filter: Dict[str, Any]
        :param operation: what operation to do. Uses MongoDB query operators (e.g $set)
        :type operation: str
        :param key: what key to change
        :type key: str
        :param value: new value for the key
        :type value: Any
        :param create_if_not_exist: create a new document if one isnt found, defaults to False
        :type create_if_not_exist: bool, optional
        :param ignore_no_matches: do not raise errors if filter doesn't match anything, defaults to False
        :type ignore_no_matches: bool, optional
        :raises FilterMatchError: if no document is found
        """
        result = self.table.update_one(
            filter, {operation: {key: value}}, upsert=create_if_not_exist
        )

        if result.matched_count == 0 and not ignore_no_matches:
            logger.error(
                f"Filter {filter} for table {self.name} couldn't match a document"
            )
            raise FilterMatchError("Filter didn't match anything")

    def create_index(self, key: str) -> None:
        """Creates a new index for a specific key

        :param key: the key to be indexed
        :type key: str
        """
        logger.info(f"Creating index on table {self.name} for key {key}")
        self.table.create_index(key)

    def delete_in_time(self, date_key: str) -> None:
        """Creates a document deletion index. `date_key` should be a DateTime object inside the document

        :param date_key: a key that references a DateTime object
        :type date_key: str
        """
        logger.info(f"Creating delete index for key {date_key} on table {self.name}")
        self.table.create_index(date_key, expireAfterSeconds=1)

    def delete_document(self, filter: Dict[str, Any]) -> int:
        logger.info(f"Deleting document with filter {filter} on table {self.name}")
        return self.table.delete_one(filter).deleted_count

    def delete_many(self, filter: Dict[str, Any]) -> int:
        logger.info(f"Deleting many with filter {filter} on table {self.name}")
        return self.table.delete_many(filter).deleted_count

    def remove_key(self, filter: Dict[str, Any], key: str) -> bool:
        updateResult = self.table.update_one(filter, {"$unset": {key: ""}})
        return updateResult.matched_count != 0
