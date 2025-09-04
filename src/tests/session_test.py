import pytest
from mock import MagicMock  # type: ignore[import-untyped]
from security.session import (
    Session,
    SessionError,
    SessionFlagError,
    SessionPermissonError,
)
from database.tables.users import Users, UserType
from database.tables.sessions import Sessions
from database.exceptions import UserNotExistError
from security.session import Session
import logging
import pyotp


logger = logging.getLogger(__name__)


class TestCreation:
    def test_creation(self, test_user: UserType, users: Users, sessions: Sessions):
        assert Session.create(
            test_user["_id"],
            "testing",
            None,
            "192.168.1.1",
            "frii.site-pytest-suite",
            users,
            sessions,
        )["success"]

        with pytest.raises(UserNotExistError):
            Session.create(
                "random-user-id",
                "testing",
                None,
                "192.168.1.1",
                "frii.site-pytest-suite",
                users,
                sessions,
            )["success"]

    def test_mfa_setup(self, test_user: UserType, users: Users, sessions: Sessions):
        session_data = Session.create(
            test_user["_id"],
            "testing",
            None,
            "192.168.1.1",
            "frii.site-pytest-suite",
            users,
            sessions,
        )

        if not session_data["access_token"]:
            logger.error("Failed to get session data")
            return

        session = Session(session_data["access_token"], users, sessions)
        mfa_result = session.create_2fa()
        url = mfa_result["url"]
        backup = mfa_result["codes"]

        refreshed_user = users.find_user({"_id": test_user["_id"]})
        session.user_cache_data = refreshed_user  # type: ignore

        code = pyotp.TOTP(pyotp.parse_uri(url).secret).now()
        assert session.verify_2fa(code)

        session.remove_mfa(backup_code=backup[0], mfa_code=None)

    def test_logging_out(self, test_user: UserType, users: Users, sessions: Sessions):
        session_data = Session.create(
            test_user["_id"],
            "testing",
            None,
            "192.168.1.1",
            "frii.site-pytest-suite",
            users,
            sessions,
        )

        if not session_data["access_token"]:
            logger.error("Failed to get session data")
            return

        session = Session(session_data["access_token"], users, sessions)
        assert session.delete(session.data["jti"])


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
