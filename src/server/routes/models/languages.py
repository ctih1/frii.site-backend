from pydantic import BaseModel
from typing import List, Dict

class ContributionBody(BaseModel):
    keys: List[Dict[str,str]]