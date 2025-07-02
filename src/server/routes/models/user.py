from pydantic import BaseModel
from typing import List

from security.api import ApiPermission


class SignUp(BaseModel):
    username: str
    password: str
    email: str
    language: str


class PasswordReset(BaseModel):
    code: str
    hashed_password: str


class MFACreation(BaseModel):
    backup_codes: List[str]
    app_link: str


class ApiCreationBody(BaseModel):
    permissions: List[ApiPermission]
    domains: List[str]
    comment: str


class ApiGetKeys(BaseModel):
    key: str
    domains: List[str]
    perms: List[ApiPermission]
    comment: str


class ApiDeletion(BaseModel):
    hash: str
