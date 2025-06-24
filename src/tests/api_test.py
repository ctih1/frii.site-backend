import pytest
from mock import MagicMock  # type: ignore[import-untyped]
from security.api import Api, ApiRangeError, ApiPermissionError, ApiError
from database.tables.users import Users
from database.tables.sessions import Sessions

valid_key: Api = MagicMock(spec=Api)
valid_key.valid = True

valid_key.permissions = ["content", "register", "get"]
valid_key.affected_domains = {"test": True, "affected": True}

invalid_key: Api = MagicMock(spec=Api)
invalid_key.valid = False


def test_requires_auth_valid_key():
    @Api.requires_auth
    def mock_function(api):
        return "Executed"

    result = mock_function(api=valid_key)
    assert result == "Executed"


def test_requires_auth_invalid_key():
    @Api.requires_auth
    def mock_function(api):
        return "Executed"

    with pytest.raises(ApiError):
        mock_function(api=invalid_key)


def test_requires_perms_valid():
    @Api.requires_auth
    @Api.requires_permission("register")
    def mock_function(api):
        return "Executed"

    result = mock_function(api=valid_key)
    assert result == "Executed"


def test_requires_perms_invalid():
    @Api.requires_auth
    @Api.requires_permission("delete")
    def mock_function(api):
        return "Executed"

    with pytest.raises(ApiPermissionError):
        mock_function(api=valid_key)


def test_modification_domain():
    @Api.requires_auth
    @Api.requires_permission("content")
    def mock_function(api, domain):
        return "Executed"

    result = mock_function(api=valid_key, domain="affected")
    assert result == "Executed"


def test_invalid_modification_domain():
    @Api.requires_auth
    @Api.requires_permission("content")
    def mock_function(api, domain):
        return "Executed"

    with pytest.raises(ApiRangeError):
        mock_function(api=valid_key, domain="unaffected")
