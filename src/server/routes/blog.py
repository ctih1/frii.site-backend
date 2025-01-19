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
from database.exceptions import (UserNotExistError, InviteException)
from security.session import Session
from security.convert import Convert

converter:Convert = Convert()
logger:logging.Logger = logging.getLogger("frii.site")

class Blog:
    def __init__(self, blog:Blogs, user_table:Users, session_table:Sessions) -> None:
        converter.init_vars(user_table,session_table)

        self.blog_table:Blogs = blog

        self.router = APIRouter(prefix="/blog")
        
        self.router.add_api_route(
            "/get",
            self.get, 
            methods=["GET"],
            responses={
                200: {"description": "Blog found"},
                404: {"description": "Blog not found"}
            },
            tags=["blog"]
        )

        self.router.add_api_route(
            "/get/all",
            self.get_all,
            methods=["GET"],
            responses={
                200: {"description":"Succesfully retrived blogs"}
            },
            tags=["blog"]
        )

        self.router.add_api_route(
            "/create",
            self.create, 
            methods=["POST"],
            responses={
                200: {"description": "Blog created"}
            },
            tags=["blog"]
        )



        logger.info("Initialized")

    def get(self, id:str) -> BlogType:
        blog:BlogType | None = self.blog_table.find_item({"_id":id}) # type: ignore[assignment]
        if blog is None:
            raise HTTPException(status_code=404)
        return JSONResponse(blog) # type:ignore[return-value]
    
    def get_all(self, amount:int=5, content_length:int|None=None) -> List[BlogType]:
        blogs:List[BlogType] = self.blog_table.get_table() # type: ignore[assignment]
        return [{k:(str(v)[:content_length] if content_length and k=="body" else v) for k,v in blog.items()} for blog in blogs][:amount] # type: ignore[return-value]


    @Session.requires_auth
    @Session.requires_permission(permission="blog")
    def create(self,body: BlogType, session:Session = Depends(converter.create)):
        return self.blog_table.create(body.title,body.body)


        
        
        
        
        
 
