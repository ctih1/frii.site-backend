from typing import List, Dict
import logging
from fastapi import APIRouter, Request, Header, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from server.routes.models.languages import ContributionBody
from database.tables.translations import Translations
from database.tables.users import Users
from database.tables.sessions import Sessions
from database.exceptions import UserNotExistError, InviteException
from security.session import Session
from security.convert import Convert

converter: Convert = Convert()
logger: logging.Logger = logging.getLogger("frii.site")


class Languages:
    def __init__(
        self, translations: Translations, user_table: Users, session_table: Sessions
    ) -> None:
        converter.init_vars(user_table, session_table)

        self.translations_table: Translations = translations

        self.router = APIRouter(prefix="/languages")

        self.router.add_api_route(
            "/percentages",
            self.percentages,
            methods=["GET"],
            responses={
                200: {
                    "description": "Returns the percentages of each language. (ex: {'en':1.0,'fr':0.8554})"
                },
            },
            tags=["translations"],
        )

        self.router.add_api_route(
            "/{language}/contribute",
            self.contribute,
            methods=["POST"],
            responses={
                200: {"description": "Contribution accepted"},
                460: {"description": "Invalid session"},
            },
            tags=["translations"],
        )

        self.router.add_api_route(
            "/{language}/missing-keys",
            self.get_missing_keys,
            methods=["GET"],
            responses={
                200: {"description": "Missing keys retrieved"},
                460: {"description": "Invalid session"},
            },
            tags=["translations"],
        )

        self.router.add_api_route(
            "/{language}/json",
            self.get_json,
            methods=["GET"],
            responses={
                200: {"description": "Missing keys retrieved"},
                404: {"description": "Language does not exist"},
            },
            tags=["translations"],
        )

        logger.info("Initialized")

    def percentages(self) -> Dict[str, float]:
        return self.translations_table.percentages

    @Session.requires_auth
    def contribute(
        self,
        language: str,
        body: ContributionBody,
        session: Session = Depends(converter.create),
    ) -> None:
        self.translations_table.add(language, body.keys, session.username)

    def get_missing_keys(self, language: str) -> List[Dict[str, str]]:
        return self.translations_table.get_missing_keys(language)

    def get_json(self, language: str) -> Dict[str, str]:
        try:
            return self.translations_table.combine_preview_and_commited(language)
        except ValueError:
            raise HTTPException(
                status_code=404, detail=f"Language {language} not found"
            )
