## How to setup?
.env keys:
```
"ENC_KEY": A fernet key (Fernet.generate_key())
"IPINFO_KEY": An API key for IPINFO. Used when an user signs up
"MONGODB_URL": A mongodb instance URL.
"PDNS_API_KEY": An API key for PowerDNS admin
"RESEND_KEY": An API key for resend, an email service. Is used when an account is created, password reset, or account deleted
"SENTRY_URL": URL for sentry. Not required, but slight code changes might be required
```


General contributing guidelines:

* Write code with type hinting
* Run pytest and mypy checks
* Push to your fork
* PR to dev branch

## How to get type checking working:
1. Install the MyPy extension from the vscode marketplace (matangover.mypy)
2. Install mypy through **pipx** (very important) `pip install pipx && pipx install mypy`
3. If typing isnt working, try restarting vscode