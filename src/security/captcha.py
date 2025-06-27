import requests
import logging
import json

logger: logging.Logger = logging.getLogger("frii.site")


class Captcha:
    def __init__(self, turnstile_key: str):
        self.turnstile_key: str = turnstile_key

    def verify(self, code: str, ip: str) -> bool:
        logger.info("Verifying captcha")
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=json.dumps(
                {"secret": self.turnstile_key, "response": code, "remoteip": ip}
            ),
            headers={"Content-Type": "application/json"},
        )

        success = response.json()["success"]
        if not success:
            logger.warning("Turnstile verification failed")
            logger.warning(response.json())
            return False

        logger.info("Captcha passed")
        return True
