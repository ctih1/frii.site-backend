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
from database.exceptions import ConflictingReferralCode

logger = logging.getLogger(__name__)


class TestMail:
    def test_creation(self, users: Users, test_user: UserType):
        with pytest.raises(ValueError):
            users.referrals.create(test_user["_id"], "1")

        with pytest.raises(ValueError):
            users.referrals.create(test_user["_id"], "ÄÄH")

        with pytest.raises(ValueError):
            users.referrals.create(test_user["_id"], "1" * 51)

        users.referrals.create(test_user["_id"], "NICE-CODE")
        assert users.referrals.check("nice-code")
        assert users.referrals.check("NICE-code")

        with pytest.raises(ValueError):
            users.referrals.create(test_user["_id"], "nice-code")

    def test_check(self, users: Users, test_user: UserType):
        assert users.referrals.check("nice-code")
        assert not users.referrals.check("nice-code2")

    def test_use(self, users: Users, test_user: UserType):
        users.referrals.use(test_user, "nice-code")

        with pytest.raises(ValueError):
            users.referrals.use(test_user, "nice-code2")

        current_max_domains = test_user["permissions"]["max-domains"]
        modified_user: UserType = users.find_user({"_id": test_user["_id"]})  # type: ignore

        assert modified_user["permissions"]["max-domains"] == current_max_domains + 1
