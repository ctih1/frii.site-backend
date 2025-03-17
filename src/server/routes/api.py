from typing import List, Dict
import time
import logging
from fastapi import APIRouter, Request, Header, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from server.routes.models.domain import DomainType
from database.table import Table
from database.tables.users import Users as UsersTable, UserType
from database.tables.invitation import Invites as InviteTable
from database.tables.domains import Domains as DomainTable, DomainFormat
from database.tables.sessions import Sessions as SessionTable
from database.exceptions import (UserNotExistError, InviteException, SubdomainError)
from security.encryption import Encryption
from security.api import Api
from security.convert import ConvertAPI
from dns_.dns import DNS
from dns_.validation import Validation
from dns_.exceptions import DNSException, DomainExistsError
from mail.email import Email

converter:ConvertAPI = ConvertAPI()
logger:logging.Logger = logging.getLogger("frii.site")


class API:
    def __init__(self, table:UsersTable, domains:DomainTable, dns:DNS) -> None:
        converter.init_vars(table)

        self.table:UsersTable = table
        self.dns:DNS = dns
        self.domains:DomainTable = domains
        self.dns_validation:Validation = Validation(domains,dns)

        self.router = APIRouter(prefix="/api")

        self.router.add_api_route(
            "/domain",
            self.register, 
            methods=["POST"],
            status_code=200,
            responses={
                200: {"description": "Domain created"},
                400: {"description": "Invalid domain name"},
                403: {"description": "Domain missing for subdomain (e.g: a.b.frii.site needs b.frii.site registered)"},
                405: {"description": "Domain limit exceeded"},
                409: {"description": "Domain already in use"},
                412: {"description": "Invalid DNS record type"},
                460: {"description": "Invalid API token"}
            },
            tags=["api","domain"]
        )

        self.router.add_api_route(
            "/domain",
            self.modify, 
            methods=["PATCH"],
            status_code=200,
            responses={
                200: {"description": "Domain modified"},
                403: {"description": "User does not own domain"},
                412: {"description": "Invalid record name or value"},
                460: {"description": "Invalid session"}
            },
            tags=["api","domain"]
        )


        self.router.add_api_route(
            "/domain",
            self.is_available, 
            methods=["GET"],
            status_code=200,
            responses={
                200: {"description": "Domain is available"},
                409: {"description": "Domain is not available"},
            },
            tags=["api","domain"]
        )
        
        self.router.add_api_route(
            "/domain",
            self.delete, 
            methods=["DELETE"],
            status_code=200,
            responses={
                200: {"description": "Domain deleted succesfully"},
                403: {"description": "Domain does not exist, or user does not own it."},
                460: {"description": "Invalid session"}
            },
            tags=["api","domain"]
        )

        logger.info("Initialized")

       

    @Api.requires_auth
    @Api.requires_permission("register")
    def register(self, body: DomainType, api:Api = Depends(converter.create)) -> None:

        if len(api.user_cache_data["domains"]) > api.user_cache_data.get("permissions",{}).get("max-domains",3):
            return HTTPException(status_code=405, detail="Domain limit exceeded")

        try:
            is_domain_available:bool = self.dns_validation.is_free(
                body.domain,
                body.type,
                api.user_cache_data["domains"]
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid record name")
        except DNSException as e:
            raise HTTPException(status_code=412, detail=f"Invalid type {e.type_}")
        except SubdomainError as e:
            raise HTTPException(status_code=403, detail=f"You need to own {e.required_domain}.frii.site before registering {body.domain}")
        except DomainExistsError:
            raise HTTPException(status_code=409, detail="Domain is already registered")
        
        if not is_domain_available:
            raise HTTPException(status_code=409,detail="Domain is not available")
        

        try:
            domain_id:str = self.dns.register_domain(
                body.domain,
                body.value,
                body.type,
                f"Registered through API user: {api.username}"
            )
        except DNSException as e:
            print(e.json)
            raise HTTPException(status_code=500, detail="DNS Registration failed")

        self.domains.modify_domain(
            api.username,
            body.domain,
            body.value,
            body.type
        )
    

    @Api.requires_auth
    @Api.requires_permission("content")
    def modify(self, body:DomainType, api:Api = Depends(converter.create)) -> None:
        clean_domain_name:str = self.domains.clean_domain_name(body.domain)
        if not self.dns_validation.record_name_valid(body.domain):
            raise HTTPException(status_code=412, detail=f"Invalid domain name {body.domain}")
        
        if not self.dns_validation.record_value_valid(body.value, body.type):
            raise HTTPException(status_code=412, detail=f"Invalid value {body.value}")
        
        if not self.dns_validation.user_owns_domain(api.username,body.domain):
            raise HTTPException(status_code=403, detail=f"You do not own the domain {body.domain}")

        id:str | None
        
        try:
            id = self.dns.modify_domain(
                api.user_cache_data["domains"][clean_domain_name]["id"],
                body.value,
                body.type,
                body.domain
            )
        

        except ValueError: # domain id is corrupt
            logger.error(f"Domain id for {body.domain} is corrupted")
            id = self.dns.get_id(body.domain,body.type,body.value)

            if id is None:
                id = self.dns.register_domain(body.domain,body.value,body.type,f"Registered with domain repair through API {api.username}")
        
        except DNSException as e:
            print(e.json)
            raise HTTPException(status_code=500)
        
        if id is None:
            raise HTTPException(status_code=501)
        
        self.domains.add_domain(
            api.username,body.domain,
            {
                "id":id,
                "ip": body.value,
                "registered": round(time.time()),
                "type":body.type
            }
        )
        

    @Api.requires_auth
    @Api.requires_permission("delete")
    def delete(self, domain:str, api:Api = Depends(converter.create)) -> None:
        if not self.domains.delete_domain(api.username,domain):
            raise HTTPException(status_code=403, detail="Domain does not exist, or user does not own it.")


    def is_available(self,name:str):
        if not self.dns_validation.is_free(name,"A",{},raise_exceptions=False):
            raise HTTPException(status_code=409, detail=f"Domain {name}.frii.site is not available")
        
    


        
        
        
        
        
 
