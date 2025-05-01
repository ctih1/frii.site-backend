import pytest
from mock import MagicMock # type: ignore[import-untyped]
from security.session import Session, SessionError, SessionFlagError, SessionPermissonError
from database.tables.users import Users
from database.tables.sessions import Sessions

valid_session = MagicMock(spec=Session)
valid_session.valid = True

valid_session.permissions = ["admin"]
valid_session.flags = ["store"]

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
        

def test_requires_flag_valid():
    @Session.requires_flag(flag="store")
    def mock_function(session):
        return "Executed"
    
    result = mock_function(session=valid_session)
    assert result == "Executed"
    
    

def test_requires_flag_invalid():
    @Session.requires_flag(flag="apex-domains")
    def mock_function(session):
        return "Executed"
    
    with pytest.raises(SessionFlagError):
        mock_function(session=valid_session)
        


    