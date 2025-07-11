from pydantic import BaseModel
from typing import List


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
    permissions: List[str]
    domains: List[str]


class ApiGetKeys(BaseModel):
    key: str
    domains: List[str]
    perms: List[str]
    comment: str
