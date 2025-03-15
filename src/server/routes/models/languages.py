from pydantic import BaseModel
from typing import List

class ContributionBody(BaseModel):
    keys: List[str]