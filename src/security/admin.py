import os
from typing import TypedDict, List
from security.session import Session
from security.encryption import Encryption
from database.tables.users import Users
from database.tables.users import UserType
from database.tables.domains import DomainFormat
from database.exceptions import UserNotExistError

user_basic_data = TypedDict("user_basic_data", {
    "username":str,
    "email": str,
    "created": int,
    "last-login": int,
    "domains": dict
})

