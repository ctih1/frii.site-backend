import os
import time
from typing import List
import resend # type:ignore[import-untyped]
import resend.exceptions # type:ignore[import-untyped]
from database.tables.codes import Codes
from database.tables.general import General
from security.encryption import Encryption
from debug.logger import Logger

verify_template = """
<head>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,100..900;1,14..32,100..900&display=swap" rel="stylesheet">
</head>
<body>
  <div id="verification" style="max-width: 500px">
    <div id="banner" style="width: 100%; display: flex; justify-content:center; align-items: center; background: radial-gradient(circle, rgba(0,123,255,1) 0%, rgba(50,125,200,1) 64%); height: 10em;">
      <img src="https://www.frii.site/favicon.svg" style="height: 8em; filter: drop-shadow(0px 2px 20px #00000055)">
    </div>
    <h1 style="margin-left: auto; margin-right:auto; width: fit-content; font-family: 'Inter', sans-serif">You're almost there!</h1>
    <div id="button-holder" style="display: flex; justify-content:center;">

      <a href="https://www.frii.site/verify/{code}" style="width: 90%; aspect-ratio:3/1; background-color: rgb(0,123,255); display: flex; justify-content:center; align-items: center; border-radius: 1.5em;  text-decoration: none;"><div id="text" style="color: white; font-size: 1.5em; font-family: 'Inter', sans-serif">Click <b>here</b> to verify your account</div></a>
    </div>
      <p style="margin-top: 200px; font-family: 'Inter', sans-serif">This code will expire in <b>45 minutes</b>. If you weren't expecting this email, make sure your accounts are secure, and you have 2 factor authentication turned on.</p>
  </div>
</body>
"""
recovery_template = """
<head>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,100..900;1,14..32,100..900&display=swap" rel="stylesheet">
</head>
<body>
  <div id="verification" style="max-width: 500px">
    <div id="banner" style="width: 100%; display: flex; justify-content:center; align-items: center; background: radial-gradient(circle, rgba(0,123,255,1) 0%, rgba(50,125,200,1) 64%); height: 10em;">
      <img src="https://www.frii.site/favicon.svg" style="height: 8em; filter: drop-shadow(0px 2px 20px #00000055)">
    </div>
    <h1 style="margin-left: auto; margin-right:auto; width: fit-content; font-family: 'Inter', sans-serif">Password recovery</h1>
    <div id="button-holder" style="display: flex; justify-content:center;">

      <a href="https://www.frii.site/account/recover?c={code}" style="width: 90%; aspect-ratio:3/1; background-color: rgb(0,123,255); display: flex; justify-content:center; align-items: center; border-radius: 1.5em;  text-decoration: none;"><div id="text" style="color: white; font-size: 1.5em; font-family: 'Inter', sans-serif">Click <b>here</b> to reset your password</div></a>
    </div>
      <p style="margin-top: 200px; font-family: 'Inter', sans-serif">This code will expire in <b>45 minutes</b>. If you weren't expecting this email, make sure your accounts are secure, and you have 2 factor authentication turned on.</p>
  </div>
</body>"""


l:Logger = Logger("email.py")

class Email():
	def __init__(self, mongo_client):
		self.table:Codes = Codes(mongo_client)
		self.general:General = General(mongo_client)
		self.encryption:Encryption = Encryption(os.getenv("ENC_KEY"))
		resend.api_key = os.getenv("RESEND_KEY")

	def is_taken(self,email:str) -> bool:
		split_email:str = email.replace("+","@") # removes ability to make alt accounts using the same email (ex. a@gmail.com, a+hi@gmail.com)
		email_parts:List[str] = split_email.split("@")
		processed_email = f"{email_parts[0]}@{email_parts[-1]}"

		email_hash:str = Encryption.sha256(processed_email+"supahcool")

		return self.table.find_item({"email-hash":email_hash}) is not None
	

	def send_verification_code(self,username:str, email:str) -> bool:
		code:str = self.table.create_code("verification",username)
		try:
			resend.Emails.send({
				"from": "send@frii.site",
				"to": email,
				"subject": "Verify your account",
				"html": verify_template.replace("{code}",code)
			})
		except resend.exceptions.ResendError as e:
			l.error(f"Failed to send email to {email} error: {e}")
			return False
		return True

	def verify(self, code:str) -> bool:
		if code not in self.table.verification_codes:
			l.info("Code is not valid: not in codes")
			return False
		
		if time.time() > self.table.verification_codes[code]["expire"]:
			l.info("Code is not valid: expired")
			del self.table.verification_codes[code]
			return False
		
		l.info(f"Code {code} is valid, verifying..")

		self.general.modify_document(
			{"_id":self.table.verification_codes[code]["account"]},
			key="verified",
			value=True,
			operation="$set"
		)

		del self.table.verification_codes[code]

		return True


	def send_password_code(self, username:str) -> bool:
		hash_username:str = Encryption.sha256(username)
		user_data: dict | None = self.general.find_item({"_id":hash_username})

		if user_data is None:
			l.info("User does not exist, abandoning verification")
			return False

		user_email = self.encryption.decrypt(user_data["email"])
	
		code = self.table.create_code("recovery",hash_username)

		try:
			resend.Emails.send({
				"from": "send@frii.site",
				"to": user_email,
				"subject": "Password recovery",
				"html": recovery_template.replace("{code}",code)
			})
		except resend.exceptions.ResendError as e:
			l.error(f"Failed to send email to {username}, error {e}")
			return False
		
		return True
	