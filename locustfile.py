from locust import HttpUser, task
import os
from dotenv import load_dotenv
import json
import random

load_dotenv()
AUTH_TOKEN = os.environ.get("TEST_ACCOUNT_TOKEN")

if not AUTH_TOKEN:
    print("Missing auth token!")
    quit()


def generate_a_value():
    return ".".join([f"{random.randint(0,9)}" for _ in range(4)])


print(generate_a_value())


class DomainTest(HttpUser):
    @task
    def modify(self):
        self.client.patch(
            "/domain/modify",
            headers={"X-Auth-Token": AUTH_TOKEN},
            data=json.dumps(
                {"domain": "loadtest", "value": f"{generate_a_value()}", "type": "A"}
            ),
        )
