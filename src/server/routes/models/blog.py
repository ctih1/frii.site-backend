from pydantic import BaseModel

class BlogType(BaseModel):
    _id: str
    date: int
    title: str
    body: str