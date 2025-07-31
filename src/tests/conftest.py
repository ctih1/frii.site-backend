import pytest
import os
import json
from database.tables.users import UserType
from pymongo import MongoClient

os.environ["RESEND_EMAIL"] = "ignore@example.com"
os.environ["PDNS_API_KEY"] = "testingtest"
os.environ["PDNS_SERVER_URL"] = "testingtest.com"
os.environ["TARGET_ZONE"] = "frii.site"
os.environ["WEBSITE_URL"] = "gääh"


def load_user() -> UserType:
    example_normal = {}
    with open(os.path.join(".", "src", "tests", "example-data", "user.json"), "r") as f:
        example_normal = json.load(f)

    return example_normal  # type: ignore[return-value]


def pytest_configure():
    pytest.example_user = load_user()
    pytest.client = MongoClient()
