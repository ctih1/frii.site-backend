import logging
import os
from cryptography.fernet import Fernet
import cryptography.fernet
import shutil
import secrets
from typing import Dict
import subprocess
import sys

ANSI = "\033["
RED = f"{ANSI}31m"
GREEN = f"{ANSI}32m"
YELLOW = f"{ANSI}33m"
PURPLE = f"{ANSI}35m"
DEBUG = f"{ANSI}90m"
RESET = f"{ANSI}0m"


class ColorLogger(logging.Formatter):
    def __init__(self, colors: bool = True):  # Disable colors for text output
        self.colors = colors

        self._format = f"[ %(levelname)-8s ]: %(message)s {DEBUG} [%(asctime)s.%(msecs)03d] (%(filename)s:%(funcName)s) {RESET}"

        self.FORMATS = {
            logging.DEBUG: DEBUG + self._format + RESET,
            logging.INFO: self._format.replace(
                "%(levelname)-8s", f"{GREEN}%(levelname)-8s{RESET}"
            ),
            logging.WARNING: YELLOW + self._format + RESET,
            logging.ERROR: RED + self._format + RESET,
            logging.CRITICAL: PURPLE + self._format + RESET,
        }

    def format(self, record: logging.LogRecord):
        if self.colors:
            log_fmt = self.FORMATS.get(record.levelno)  # Add colors
        else:
            log_fmt = self._format  # Just use the default format

        formatter = logging.Formatter(log_fmt, datefmt="%m/%d/%y %H:%M:%S")
        return formatter.format(record)


logger = logging.getLogger("goober")
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(ColorLogger())

file_handler = logging.FileHandler("log.txt", mode="w+", encoding="UTF-8")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(ColorLogger(colors=False))

logger.addHandler(console_handler)
logger.addHandler(file_handler)


def setup() -> None:
    logger.info("Starting setup...")

    if os.path.exists(os.path.join(".", ".env")):
        logger.critical(
            ".env file already exist! If you wish to delete/override the .env file, any existing accounts will become bricked due to the encryption key (ENC_KEY) being lost. This also means that you cannot register new domains, due to them already existing inside PowerDNS"
        )
        agreed = (
            input("I know what will happen and I want to continue: <y|n>: ").lower()
            == "y"
        )

        if agreed:
            shutil.move(os.path.join(".", ".env"), os.path.join(".", ".env.backup"))
            logger.warning(
                f".env file has not been deleted, but moved to {os.path.abspath(os.path.join('.', '.env.backup'))}"
            )
        else:
            logger.warning("Aborting...")
            quit(1)

    logger.info("Creating an encryption key...")
    enc_key = Fernet.generate_key().decode("utf-8")

    logger.info("Creating JWT secret")
    jwt_secret = secrets.token_urlsafe(64)

    logger.info("Starting user portion of setup...")

    logger.info("Let's setup PowerDNS. You'll need: PowerDNS, and PowerDNS-Admin")
    logger.info(
        "There are many good guides, but it is best to follow a guide meant for your system"
    )
    logger.info('Try searching for "how to setup powerdns and powerdns admin on (os)"')

    powerdns_url = input(
        "Enter your PowerDNS-Admin URL / IP (e.g https://dns.example.com, http://243.22.122.42): "
    )

    if not powerdns_url.startswith("http://") and not powerdns_url.startswith(
        "https://"
    ):
        is_https = input("Does your domain support HTTPS? <y|n>").lower() == "y"

        if is_https:
            logger.info(f"Setting access url as https://{powerdns_url}")
            powerdns_url = "https://" + powerdns_url
        else:
            logger.info(f"Setting access url as http://{powerdns_url}")
            powerdns_url = "http://" + powerdns_url

    powerdns_domain = input(
        "Enter your target domain (e.g frii.site, or example.com): "
    )
    if powerdns_domain.endswith("."):
        logger.warning("Target domain ends with a dot, removing...")
        powerdns_domain = powerdns_domain[:-1]

    powerdns_api_key = input("Enter your PowerDNS API key: ")

    logger.info("To retrieve your IPINFO key, go to https://ipinfo.io/dashboard/token")
    ipinfo_key = input("Enter your IPINFO key: ")

    if len(ipinfo_key) != 14:
        logger.warning(
            "IPINFO key potentially incorrect, expected 14 characters. Continuing regardles..."
        )

    logger.info(
        "To get a MongoDB connection URL, either setup a free instance on www.mongodb.com, or if you wish to self host, follow this: https://www.mongodb.com/docs/manual/installation/"
    )
    mongodb_url = input(
        "Enter a valid MongoDB connection URL (mongodb:// or mongodb+srv://): "
    )

    if not mongodb_url.startswith("mongodb"):
        logger.error(
            "Invalid MonogDB URL! It should start with either mongodb+srv:// or mongodb://"
        )

    logger.info(
        "This is used for sending emails, to get your API key, register an account on resend.com, and get your API key from here: https://resend.com/api-keys"
    )
    resend_key = input("Enter your Resend API key: ")

    logger.info("Enter the resend email you setup")
    resend_email = input("Resend email (e.g contact@domain.tld): ")

    if not resend_key.startswith("re_"):
        logger.warning(
            "It is highly likely that you have given an invalid Resend key, as it does not start with re_ . Ignoring since the format might have changed."
        )

    logger.info(
        "Cloudflare Turnstile key is used for Captchas on the frontend, but is still required. go to dash.cloudflare.com, then select 'Turnstile' from the sidebar, press 'add widget', add a hostname (AND localhost), press 'create', and copy 'Secret Key'. (NOTE: While you're here, copy Site Key for the website later)"
    )
    logger.info("If you wish to disable turnstile, press enter")
    turnstile_key = input("Enter your turnstile key: ")

    if len(turnstile_key) < 1:
        logger.info("Defaulting to an always passing token")
        turnstile_key = (
            "1x0000000000000000000000000000000AA"  # A key that always passes
        )

    logger.info("(Optional): A discord webhook for analytics (such as sign ups)")
    dc_webhook = input("Enter a discord webhook link (press enter to skip): ")

    logger.info(
        "Enter the URL to your frontend instance. This is used for password and account recovery"
    )
    frontend_url = input("Frontend URL (e.g https://www.another.frii.site): ")

    write_env_file(
        {
            "ENC_KEY": enc_key,
            "JWT_KEY": jwt_secret,
            "IPINFO_KEY": ipinfo_key,
            "MONGODB_URL": mongodb_url,
            "RESEND_KEY": resend_key,
            "RESEND_EMAIL": resend_email,
            "TURNSTILE_KEY": turnstile_key,
            "DC_WEBHOOK": dc_webhook,
            "TARGET_ZONE": powerdns_domain,
            "PDNS_API_KEY": powerdns_api_key,
            "PDNS_SERVER_URL": powerdns_domain,
            "WEBSITE_URL": frontend_url,
        }
    )

    logger.info("Setting up requirements...")
    subprocess.run(sys.executable)


def write_env_file(env_keys: Dict[str, str]) -> None:
    logger.info(f"Generating .env file with {len(env_keys)} keys")
    lines = ""
    for key, val in env_keys.items():
        lines += f'{key.upper()}="{val}"\n'

    with open(os.path.join(".", ".env"), "w") as f:
        f.write(lines)
        logger.info("Succesfully saved .env!")


if __name__ == "__main__":
    setup()
    logger.info("Next steps:")
    logger.info("Install dependencies with pip (or pip3) install -r requirements.txt")
    logger.info("Tweak CORS supported domains in src/server/main.py")
    logger.info("Install uvicorn (pip install uvicorn) to run the server")
    logger.info("Run the server with 'python (or python3) src/main.py run'")
