from pydantic import BaseModel


class DomainType(BaseModel):
    domain: str
    value: str
    type: str
