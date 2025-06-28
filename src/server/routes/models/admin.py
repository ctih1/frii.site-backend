from pydantic import BaseModel
from typing import List


class BanUser(BaseModel):
    user_id: str
    reasons: List[str]
