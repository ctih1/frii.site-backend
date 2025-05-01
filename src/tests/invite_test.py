import pytest
import os
import logging
from mock import MagicMock, patch, Mock # type: ignore[import-untyped]
from contextlib import contextmanager
from mail.email import Email
from database.exceptions import SubdomainError
from database.tables.invitation import Invites
from database.exceptions import InviteException
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.results import UpdateResult

from database.tables.users import Users
from database.tables.codes import Codes

logger = logging.getLogger(__name__)

def safe_enc_init(self, *args, **kwargs):
    self.fernet = MagicMock()
    
invites = None

mongo_client = MagicMock(spec=MongoClient)
db = MagicMock()
collection = MagicMock()
mongo_client.__getitem__.return_value = db
db.__getitem__.return_value = collection
collection.find_one.return_value = pytest.example_user # type: ignore
collection.update_one = lambda *args, **kwargs: MagicMock(spec=UpdateResult)

# If we dont patch Encryption, fernet will throw an exception
with patch("security.encryption.Encryption.__init__",safe_enc_init):
    invites = Invites(mongo_client)

class TestInviteValidation:
    def test_valid_invite(self):
        assert invites.is_valid("zc8qcUcMLNqE3Dbj")
    
    def test_used_invite(self):
        assert not invites.is_valid("6MY6Y1YE05Wfkex9")
        
    def test_invalid_invite_code(self):
        assert not invites.is_valid("9xekfW50EY1Y6YM6")
    
    def test_invalid_invite_length(self):
        assert not invites.is_valid("Hello")

class TestInviteCreation:
    def test_invite_creation(self):
        assert invites.create(pytest.example_user)
    
    def test_invite_creation_too_many(self):
        # Add invite so invite limit is reached
        pytest.example_user["invites"]["third_invite"] = {} 
        
        with pytest.raises(InviteException):
            invites.create(pytest.example_user)
    
    
    