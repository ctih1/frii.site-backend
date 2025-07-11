from typing import List, Annotated
import time
import logging
from fastapi import APIRouter, Request, Header, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from server.routes.models.blog import BlogType
from database.tables.blogs import Blogs
from database.tables.users import Users
from database.tables.sessions import Sessions
from database.exceptions import UserNotExistError, InviteException
from security.session import Session
from security.convert import Convert

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("frii.site")


class Blog:
    def __init__(self, blog: Blogs, user_table: Users, session_table: Sessions) -> None:
        converter.init_vars(user_table, session_table)

        self.blog_table: Blogs = blog

        self.router = APIRouter(prefix="/blog")

        self.router.add_api_route(
            "/get",
            self.get,
            methods=["GET"],
            responses={
                200: {"description": "Blog found"},
                404: {"description": "Blog not found"},
            },
            tags=["blog"],
        )

        self.router.add_api_route(
            "/get/all",
            self.get_all,
            methods=["GET"],
            responses={200: {"description": "Succesfully retrived blogs"}},
            tags=["blog"],
        )

        self.router.add_api_route(
            "/create",
            self.create,
            methods=["POST"],
            responses={
                200: {"description": "Blog created"},
                460: {"description": "Invalid session"},
            },
            tags=["blog"],
        )

        logger.info("Initialized")

    def get(self, id: str) -> BlogType:
        blog: BlogType | None = self.blog_table.find_item({"_id": id})  # type: ignore[assignment]
        if blog is None:
            raise HTTPException(status_code=404)
        return JSONResponse(blog)  # type:ignore[return-value]

    def get_all(self, n: int = 5, content: int | None = None) -> List[BlogType]:
        amount = n
        content_length = content
        blogs = self.blog_table.get_table()  # type: ignore[assignment]
        formatted_blogs: List[BlogType] = []

        for blog in blogs:
            new_blog: BlogType = BlogType(
                url=blog["_id"],
                date=blog["date"],
                title=blog["title"],
                body=blog["body"][:content_length],
            )
            formatted_blogs.append(new_blog)

        formatted_blogs = sorted(
            formatted_blogs, key=lambda blog: blog.date, reverse=True
        )

        return formatted_blogs[:amount]

    @Session.requires_auth
    @Session.requires_permission(permission="blog")
    def create(self, body: BlogType, session: Session = Depends(converter.create)):
        return self.blog_table.create(body.title, body.body)
