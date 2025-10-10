import pytest
import os
import json
from database.tables.users import UserType, Users
from database.tables.codes import Codes
from database.tables.domains import Domains
from database.tables.sessions import Sessions
from database.tables.reward_codes import Rewards
from dns_.validation import Validation
from dns_.dns import DNS
from security.encryption import Encryption
from security.session import Session


def load_user() -> UserType:
    example_normal = {}
    with open(os.path.join(".", "src", "tests", "example-data", "user.json"), "r") as f:
        example_normal = json.load(f)

    return example_normal  # type: ignore[return-value]


import os
import pymongo
from cryptography.fernet import Fernet
import secrets
from database.tables.users import Users
from mail.email import Email
import time
from dotenv import load_dotenv

load_dotenv()

client: pymongo.MongoClient = pymongo.MongoClient(os.environ["MONGODB_TEST_URL"])

country_data = {
    "ip": "176.92.136.59",
    "hostname": "176-92-136-59.example.isp",
    "city": "Helsinki",
    "region": "Uusimaa",
    "country": "FI",
    "loc": "60.1695,24.9354",
    "org": "AS16086 Example ISP",
    "postal": "00100",
    "timezone": "Europe/Helsinki",
    "country_name": "Finland",
    "isEU": True,
    "country_flag_url": "https://cdn.ipinfo.io/static/images/countries-flags/FI.svg",
    "country_flag": {
        "emoji": "🇫🇮",
        "unicode": "U+1F1EB U+1F1EE",
    },
    "country_currency": {"code": "EUR", "symbol": "€"},
    "continent": {"code": "EU", "name": "Europe"},
    "latitude": "60.1695",
    "longitude": "24.9354",
}


# The database is wiped every run, so it's okay to reset these
def init_env():
    print("Initializing environment varss")
    os.environ["ENC_KEY"] = Fernet.generate_key().decode("utf-8")
    os.environ["JWT_KEY"] = secrets.token_urlsafe(64)

    client = pymongo.MongoClient(os.environ["MONGODB_TEST_URL"])
    if not os.environ["MONGODB_TEST_URL"].startswith(
        "mongodb://192.168"
    ) and not os.environ["MONGODB_TEST_URL"].startswith("mongodb://localhost"):
        print(
            f"WARNING: test db url: {os.environ['MONGODB_TEST_URL']}. Are you sure it's real?"
        )
        quit()

    for db in client.list_database_names():
        if db == "admin":
            continue

        dab = client.get_database(db)
        for collection in dab.list_collection_names():
            dab.get_collection(collection).drop()

        client.drop_database(db)
    time.sleep(1)


init_env()

_users = Users(client)
_codes = Codes(client)
_encryption = Encryption(os.environ["ENC_KEY"])
_email = Email(_codes, _users, _encryption)
_domains = Domains(client)
_dns = DNS(_domains)
_validation = Validation(_domains, _dns)
_sessions = Sessions(client)
_rewards = Rewards(client, _users)


def create_first_user():
    client = pymongo.MongoClient(os.environ["MONGODB_TEST_URL"])

    user_id = _users.create_user(
        "testing",
        "testing",
        "testing@email.com",
        "en-US",
        country_data,
        time.time(),
        _email,
        "TESTING_ENV",
        dont_send_email=True,
    )

    _users.modify_document({"_id": user_id}, "$set", "verified", True)

    os.environ["USER_ID"] = user_id
    client.close()


create_first_user()
_test_user = _users.find_user({"_id": _encryption.sha256("testing")})
_test_session = Session.create(
    _test_user["_id"],  # type: ignore
    "testing",
    None,
    "192.168.1.1",
    "frii.site-pytest-suite",
    _users,
    _sessions,
)


@pytest.fixture(scope="session")
def mongo_client():
    yield client
    client.close()


@pytest.fixture(scope="session")
def users():
    yield _users


@pytest.fixture(scope="session")
def email():
    yield _email


@pytest.fixture(scope="session")
def encryption():
    yield _encryption


@pytest.fixture(scope="session")
def codes():
    yield _codes


@pytest.fixture(scope="session")
def domains():
    yield _domains


@pytest.fixture(scope="session")
def validation():
    yield _validation


@pytest.fixture(scope="session")
def sessions():
    yield _sessions


@pytest.fixture(scope="session")
def rewards():
    yield _rewards


@pytest.fixture(scope="session")
def test_session():
    assert _test_session["access_token"]
    yield Session(_test_session["access_token"], _users, _sessions)


@pytest.fixture(scope="session")
def test_session_refresh():
    yield _test_session["refresh_token"]


@pytest.fixture(scope="session")
def test_user():
    yield _test_user
