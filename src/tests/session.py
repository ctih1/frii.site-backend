import pytest
import os

print(os.curdir)

from security.session import Session, SessionError, SessionPermissonError
from mock import MagicMock

valid_session = MagicMock(spec=Session)
valid_session.valid = True
valid_session.permissions = ["admin"]

invalid_session = MagicMock(spec=Session)
invalid_session.valid = False

def test_requires_auth_valid_session():
    @Session.requires_auth
    def mock_function(session):
        return "Executed"

    result = mock_function(session=valid_session)
    assert result == "Executed"

def test_requires_auth_invalid_session():
    @Session.requires_auth
    def mock_function(session):
        return "Executed"

    with pytest.raises(SessionError): 
        mock_function(session=invalid_session)

        
def test_requires_perms_valid():
    @Session.requires_permission("admin")
    def mock_function(session):
        return "Executed"
    
    result = mock_function(session=valid_session)
    assert result == "Executed"

def test_requires_perms_invalid():
    @Session.requires_permission("blogs")
    def mock_function(session):
        return "Executed"
    
    with pytest.raises(SessionPermissonError):
        mock_function(session=valid_session)