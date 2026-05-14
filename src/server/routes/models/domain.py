from pydantic import BaseModel
from typing import Dict, List
from database.tables.domains import DomainFormat
from dns_.types import TYPES


class DomainType(BaseModel):
    domain: str
    values: List[str]
    type: TYPES


class DomainRetrieve(BaseModel):
    domains: Dict[str, DomainFormat]
    owned_tlds: List[str]
