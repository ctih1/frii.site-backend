from pydantic import BaseModel
from typing import Dict, List
from database.tables.domains import DomainFormat


class DomainType(BaseModel):
    domain: str
    value: str
    type: str


class DomainRetrieve(BaseModel):
    domains: Dict[str, DomainFormat]
    owned_tlds: List[str]
