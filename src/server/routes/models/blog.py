from pydantic import BaseModel


class BlogType(BaseModel):
    url: str
    date: int
    title: str
    body: str
