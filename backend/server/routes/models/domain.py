from pydantic import BaseModel

class DomainType(BaseModel):
    domain: str
    value: str
    type: str

class RawDomainType(BaseModel):
    ip:str
    type:str
    registered: int | float
    id: str