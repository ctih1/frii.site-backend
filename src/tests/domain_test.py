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
from dns_.dns import DNS
import time
from dns_.validation import Validation

logger = logging.getLogger(__name__)


class TestDomainValidation:
    def test_valid_name(self):
        assert Validation.record_name_valid("example-domain", "A")

    def test_valid_subdomain(self):
        assert Validation.record_name_valid("example.domain", "A")

    def test_invalid_name(self):
        assert not Validation.record_name_valid("Invälid_Recörd_Nämë", "A")

    def test_invalid_start_and_end(self):
        assert not Validation.record_name_valid("example.", "A")
        assert not Validation.record_name_valid(".example", "A")

    def test_txt_record(self):
        assert Validation.record_name_valid("_verification", "TXT")

    def test_underscore_not_txt_record(self):
        assert not Validation.record_name_valid("_verification", "A")

    def test_valid_content(self):
        assert Validation.record_value_valid("1.2.3.4", "A")

    def test_invalid_type(self):
        assert not Validation.record_value_valid("0.0.0.0", "C")

    def test_invalid_content_for_type(self):
        assert not Validation.record_value_valid("test.cname.fi", "A")

    def test_domain_clean(self):
        assert Domains.clean_domain_name("a.b") == "a[dot]b"
        assert Domains.beautify_domain_name(None, "a[dot]b") == "a.b"  # type: ignore


class TestDomainUser:
    def test_register(self, domains: Domains, users: Users, test_user: UserType):
        domains.add_domain(test_user["_id"], "TEST", {"id": None, "ip": "1.2.3.4", "registered": round(time.time()), "type": "A"})  # type: ignore
        updated_user_data: UserType | None = users.find_user({"_id": test_user["_id"]})
        if updated_user_data is None:
            pytest.fail("Could not retrieve new user data")

        assert updated_user_data.get("domains", {}).get("TEST") is None
        assert updated_user_data.get("domains", {}).get("test") is not None

        users.modify_document(
            {"_id": test_user["_id"]},
            "$set",
            "domains.TEST3",
            {"ip": "0.0.0.0", "type": "A", "registered": time.time()},
        )

        updated_user_data = users.find_user({"_id": test_user["_id"]})
        if updated_user_data is None:
            pytest.fail("Could not retrieve new user data")

        assert updated_user_data.get("domains", {}).get("TEST3") is None
        assert updated_user_data.get("domains", {}).get("test3") is not None
        users.remove_key({"_id": test_user["_id"]}, "domains.test2")

    def test_domain_not_free(self, validation: Validation, domains: Domains):
        assert not validation.is_free("test", "A", {}, False)
        assert validation.is_free("test2", "A", {}, False)

    def test_domain_limits(self, test_user: UserType, users: Users):
        # First test the default domain limit
        assert Validation.can_user_register("test2", test_user)[0]
        assert Validation.can_user_register("subdomain.test2", test_user)[0]

        # Change domain limit to be 0. This stops the user from creating new domains, but still allows them to create subdomains
        users.modify_document(
            {"_id": test_user["_id"]}, "$set", "permissions.max-domains", 0
        )

        modified_user = users.find_user({"_id": test_user["_id"]})
        if not modified_user:
            logger.critical("Failed to get testing account")
            quit()

        assert not Validation.can_user_register("test2", modified_user)[0]
        assert Validation.can_user_register("subdomain.test2", modified_user)[0]

        # Disable subdomain registration too
        users.modify_document(
            {"_id": test_user["_id"]}, "$set", "permissions.max-subdomains", 0
        )

        modified_user = users.find_user({"_id": test_user["_id"]})
        if not modified_user:
            logger.critical("Failed to get testing account")
            quit()

        assert not Validation.can_user_register("subdomain.test2", modified_user)[0]

        users.modify_document(
            {"_id": test_user["_id"]}, "$set", "permissions.max-subdomains", 50
        )

        users.modify_document(
            {"_id": test_user["_id"]}, "$set", "permissions.max-domains", 3
        )
