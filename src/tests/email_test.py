import pytest
import os
import logging
from mock import MagicMock, patch # type: ignore[import-untyped]
from mail.email import Email
from database.exceptions import SubdomainError
from database.tables.domains import Domains
from database.tables.domains import Domains
from database.tables.users import Users
from database.tables.codes import Codes

logger = logging.getLogger(__name__)

def user_side_effect(*args, **kwargs): 
    if args[0]["email-hash"] == pytest.example_user["email-hash"]:
        return pytest.example_user

mock_users = MagicMock(spec=Users)
mock_users.find_item.side_effect = user_side_effect

email = Email(MagicMock(spec=Codes),mock_users, MagicMock())

class TestMailValidation:
    def test_taken_email(self):
        assert email.is_taken("testmail@mail.com")
        
    def test_alternate_taken_email(self):
        assert email.is_taken("testmail+another@mail.com")

    def test_test_not_taken(self):
        assert not email.is_taken("markkumail@mail.com")
    