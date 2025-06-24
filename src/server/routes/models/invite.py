from pydantic import BaseModel


class InviteCreate(BaseModel):
    code: str
