import pytest
import pymongo
import os
import logging
from mock import MagicMock, patch  # type: ignore[import-untyped]
from mail.email import Email
from database.exceptions import SubdomainError
from database.tables.domains import Domains
from database.tables.domains import Domains
from database.tables.users import Users, UserType
from database.tables.codes import Codes

logger = logging.getLogger(__name__)


class TestMail:
    def test_use_detection(self, email: Email):
        assert email.is_taken("testing@email.com")
        assert email.is_taken("testing+alt@email.com")
        assert not email.is_taken("free@email.com")

    def test_verification(self, codes: Codes, email: Email, test_user: UserType):
        code = codes.create_code("verification", test_user["_id"])
        assert email.verify(code)
        assert not email.verify("fakecode")
