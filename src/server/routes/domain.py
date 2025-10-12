from typing import List, Dict, get_args
import time
import logging
from fastapi import APIRouter, Request, Header, Depends, WebSocket
from collections import deque
from threading import Thread
import asyncio
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from server.routes.models.domain import DomainType, DomainRetrieve
from database.table import Table
from database.tables.users import Users as UsersTable, UserType
from database.tables.invitation import Invites as InviteTable
from database.tables.domains import Domains as DomainTable, DomainFormat
from database.tables.sessions import Sessions as SessionTable
from database.exceptions import UserNotExistError, InviteException, SubdomainError
from security.encryption import Encryption
from security.session import Session, SessionCreateStatus
from security.convert import Convert
from dns_.dns import DNS
from dns_.types import AVAILABLE_TLDS
from dns_.validation import Validation
from dns_.exceptions import DNSException, DomainExistsError
from mail.email import Email

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("frii.site")


class Domain:
    def __init__(
        self, table: UsersTable, sessions: SessionTable, domains: DomainTable, dns: DNS
    ) -> None:
        converter.init_vars(table, sessions)

        self.session_table = sessions
        self.table: UsersTable = table
        self.dns: DNS = dns
        self.domains: DomainTable = domains
        self.dns_validation: Validation = Validation(domains, dns)
        self.verification_queue: deque = deque([])
        self.verification_dict: Dict[str, str] = {}
        self.current_queue_user: str = ""

        Thread(target=self.handle_deque).start()

        self.router = APIRouter(prefix="/domain")

        self.router.add_api_route(
            "/register",
            self.register,
            methods=["POST"],
            status_code=200,
            responses={
                200: {"description": "Domain created"},
                400: {"description": "Invalid domain name"},
                401: {"description": "TLD not owned"},
                403: {
                    "description": "Domain missing for subdomain (e.g: a.b.frii.site needs b.frii.site registered)"
                },
                405: {"description": "Domain limit exceeded"},
                409: {"description": "Domain already in use"},
                412: {"description": "Invalid DNS record type"},
                460: {"description": "Invalid session"},
            },
            tags=["domain"],
        )

        self.router.add_api_route(
            "/modify",
            self.modify,
            methods=["PATCH"],
            status_code=200,
            responses={
                200: {"description": "Domain modified"},
                403: {"description": "User does not own domain"},
                412: {"description": "Invalid record name or value"},
                460: {"description": "Invalid session"},
            },
            tags=["domain"],
        )

        self.router.add_api_route(
            "/available",
            self.is_available,
            methods=["GET"],
            status_code=200,
            responses={
                200: {"description": "Domain is available"},
                409: {"description": "Domain is not available"},
            },
            tags=["domain"],
        )

        self.router.add_api_route(
            "/delete",
            self.delete,
            methods=["DELETE"],
            status_code=200,
            responses={
                200: {"description": "Domain deleted succesfully"},
                403: {"description": "Domain does not exist, or user does not own it."},
                460: {"description": "Invalid session"},
            },
            tags=["domain"],
        )

        self.router.add_api_route(
            "/get",
            self.get_domains,
            methods=["GET"],
            status_code=200,
            responses={
                200: {"description": "Returns a JSON dict of domains"},
                460: {"description": "Invalid session"},
            },
            tags=["domain"],
        )

        self.router.add_api_route(
            "/vercel/join",
            self.vercel_queue_join,
            methods=["POST"],
            responses={
                200: {"description": "Joined queue"},
                460: {"description": "Invalid session"},
            },
            tags=["domain", "vercel"],
        )

        self.router.add_api_route(
            "/vercel/get",
            self.vercel_queue_get,
            methods=["GET"],
            responses={
                200: {"description": "Position in queue"},
                404: {"description": "User not in queue"},
                460: {"description": "Invalid session"},
            },
            tags=["domain", "vercel"],
        )

        logger.info("Initialized")

    @Session.requires_auth
    def register(self, body: DomainType, session: Session = Depends(converter.create)):
        domain_name = body.domain
        if not domain_name.endswith(get_args(AVAILABLE_TLDS)):
            logger.warning("Deprecated usage of register. Please pass the TLD!")
            domain_name += ".frii.site"

        (_, tld) = self.domains.seperate_domain_into_parts(domain_name)

        if tld not in session.user_cache_data.get("owned-tlds", ["frii.site"]):
            raise HTTPException(
                status_code=401,
                detail=f"User must purchase {tld} before registering this domain",
            )

        can_user_register = self.dns_validation.can_user_register(
            body.domain, session.user_cache_data
        )

        if not can_user_register.success:
            raise HTTPException(status_code=405, detail=can_user_register.comment)

        try:
            is_domain_available: bool = self.dns_validation.is_free(
                body.domain, body.type, session.user_cache_data["domains"]
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid record name")
        except DNSException as e:
            raise HTTPException(status_code=412, detail=f"Invalid type {e.type_}")
        except SubdomainError as e:
            raise HTTPException(
                status_code=403,
                detail=f"You need to own {e.required_domain} before registering {body.domain}",
            )
        except DomainExistsError:
            raise HTTPException(status_code=409, detail="Domain is already registered")

        if not is_domain_available:
            raise HTTPException(status_code=409, detail="Domain is not available")

        success = self.dns.register_domain(
            body.domain,
            body.value,
            body.type,
            f"Registered through website user: {session.username}",
        )

        if not success:
            logger.error("DNS registration failed")
            raise HTTPException(status_code=500, detail="DNS Registration failed")

        self.domains.add_domain(
            session.username,
            body.domain,
            {
                "id": "None",
                "type": body.type,
                "ip": body.value,
                "registered": round(time.time()),
            },
        )

    @Session.requires_auth
    def modify(self, body: DomainType, session: Session = Depends(converter.create)):
        clean_domain_name: str = self.domains.clean_domain_name(body.domain)
        if not self.dns_validation.record_name_valid(body.domain, body.type):
            raise HTTPException(
                status_code=412, detail=f"Invalid domain name {body.domain}"
            )

        if not self.dns_validation.record_value_valid(body.value, body.type):
            raise HTTPException(status_code=412, detail=f"Invalid value {body.value}")

        if not self.dns_validation.user_owns_domain(
            session.username, body.domain, session.user_cache_data
        ):
            raise HTTPException(
                status_code=403, detail=f"You do not own the domain {body.domain}"
            )

        old_type: str = session.user_cache_data["domains"][clean_domain_name]["type"]

        db_thread = Thread(
            target=self.domains.add_domain,
            args=(
                session.username,
                body.domain,
                {
                    "id": "None",
                    "ip": body.value,
                    "registered": round(time.time()),
                    "type": body.type,
                },
            ),
        )
        db_thread.start()

        try:
            success = self.dns.modify_domain(
                body.value,
                body.type,
                old_type,
                body.domain,
                session.username,
            )

            if not success:
                db_thread.join()
                self.domains.delete_domain(session.user_cache_data["_id"], body.domain)
                raise DNSException("Not succesful", {"success": success})

        except DNSException as e:
            print(e.json)
            raise HTTPException(status_code=500)

        db_thread.join()

    @Session.requires_auth
    def get_domains(
        self, session: Session = Depends(converter.create)
    ) -> DomainRetrieve:
        domains: Dict[str, DomainFormat] = session.user_cache_data["domains"]
        domains = {k.replace("[dot]", "."): v for k, v in domains.items()}

        return JSONResponse({"domains": domains, "owned-tlds": session.user_cache_data.get("owned-tlds", ["frii.site"])})  # type: ignore[return-value]

    @Session.requires_auth
    def delete(self, domain: str, session: Session = Depends(converter.create)) -> None:
        if not self.domains.delete_domain(session.username, domain):
            raise HTTPException(
                status_code=403,
                detail="Domain does not exist, or user does not own it.",
            )

        if not session.user_cache_data:
            return None

        domain_type: str | None = (
            session.user_cache_data.get("domains", {})  # type: ignore[call-overload]
            .get(self.domains.clean_domain_name(domain), {})
            .get("type")
        )

        if domain_type is None:
            return None

        self.dns.delete_domain(domain, domain_type)

    def is_available(self, name: str):
        if not self.dns_validation.is_free(name, "A", {}, raise_exceptions=False):
            raise HTTPException(
                status_code=409, detail=f"Domain {name}.frii.site is not available"
            )

    def handle_deque(self) -> None:
        while True:
            while len(self.verification_queue) != 0:
                user_id: str = self.verification_queue[0]
                verification_value: str | None = self.verification_dict.get(user_id)

                if verification_value is None:
                    logger.error("Verification value not found")
                    continue

                logger.info("Updating vercel verification...")

                self.dns.modify_domain(
                    verification_value, "TXT", "TXT", "_vercel", user_id, 15
                )
                self.current_queue_user = user_id

                time.sleep(45)
                self.verification_queue.popleft()
            time.sleep(1)

    @Session.requires_auth
    def vercel_queue_join(
        self, value: str, session: Session = Depends(converter.create)
    ):
        if session.user_id not in self.verification_queue:
            self.verification_queue.append(session.user_id)
        else:
            logger.info("User already in queue")
        self.verification_dict[session.user_id] = value

    @Session.requires_auth
    def vercel_queue_get(self, session: Session = Depends(converter.create)) -> int:
        if session.user_id not in self.verification_queue:
            raise HTTPException(
                status_code=404,
                detail="User not in the queue. (see /domain/vercel/join)",
            )

        if session.user_id == self.current_queue_user:
            raise HTTPException(status_code=408, detail="Domain is currently on")

        return self.verification_queue.index(session.user_id)
