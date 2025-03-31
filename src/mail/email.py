import os
import time
from typing import List, TYPE_CHECKING
import logging
import resend # type:ignore[import-untyped]
import resend.exceptions # type:ignore[import-untyped]
from security.encryption import Encryption

if TYPE_CHECKING:
	from database.tables.codes import Codes
	from database.tables.users import Users, UserType


template_path:str = os.path.join(".","src","mail","templates")

verify_template:str
recovery_template:str
deletion_template:str

with open(os.path.join(template_path,"verify.html"),"r") as f:
	verify_template = "\n".join(f.readlines())

with open(os.path.join(template_path,"deletion.html"),"r") as f:
	deletion_template = "\n".join(f.readlines())

with open(os.path.join(template_path,"recovery.html"),"r") as f:
	recovery_template = "\n".join(f.readlines())

logger:logging.Logger = logging.getLogger("frii.site")

class Email:
	def __init__(self, codes:'Codes', users:'Users'):
		self.codes:Codes = codes
		self.users:'Users' = users
		self.encryption:Encryption = Encryption(os.getenv("ENC_KEY")) # type: ignore[arg-type]
		resend.api_key = os.getenv("RESEND_KEY")

	def is_taken(self,email:str) -> bool:
		replaced_email:str = email.replace("+","@") # removes ability to make alt accounts using the same email (ex. a@gmail.com, a+hi@gmail.com)
		email_parts:List[str] = replaced_email.split("@")
		processed_email = f"{email_parts[0]}@{email_parts[-1]}"

		email_hash:str = Encryption.sha256(processed_email+"supahcool")

		return self.users.find_item({"email-hash":email_hash}) is not None
	

	def send_verification_code(self,username:str, email:str) -> bool:
		code:str = self.codes.create_code("verification",username)
		try:
			resend.Emails.send({
				"from": "send@frii.site",
				"to": email,
				"subject": "Verify your account",
				"html": verify_template.replace("{{link}}",f"https://www.frii.site/verify/{code}"),
				"text": f"Go to https://www.frii.site/verify/{code} to verify your account"
			})
		except resend.exceptions.ResendError as e:
			logger.error(f"Failed to send verification code {e.suggested_action}")
			return False
		return True

	def verify(self, code:str) -> bool:
		if code not in self.codes.verification_codes:
			logger.debug(f"Code {code} is not valid: Nonexistant")
			return False
		
		if time.time() > self.codes.verification_codes[code]["expire"]:
			logger.debug(f"Code {code} is not valid: Expired")
			del self.codes.verification_codes[code]
			return False
		
		logger.info(f"Code {code} is valid... continuing")
		user_id:str = self.codes.verification_codes[code]["account"]
		self.users.modify_document(
			{"_id":user_id},
			key="verified",
			value=True,
			operation="$set"
		)

		logger.info(f"Verified user {user_id}")

		del self.codes.verification_codes[code]

		return True
	
	def send_delete_code(self, username:str, email:str) -> bool:
		code:str = self.codes.create_code("deletion",username)
		try:
			resend.Emails.send({
				"from": "send@frii.site",
				"to": email,
				"subject": "Account deletion",
				"html": deletion_template.replace("{{link}}",f"https://www.frii.site/verify/{code}"),
				"text": f"Go to https://www.frii.site/verify/{code} to verify your account"
			})
   			
		except resend.exceptions.ResendError as e:
			logger.error(f"Failed to send verification code {e.suggested_action}")
			return False

		logger.info(f"Sent account deletion code to username {username}")
		return True
	

	def send_password_code(self, username:str) -> bool:
		hash_username:str = Encryption.sha256(username)
		user_data: 'UserType' | None = self.users.find_user({"_id":hash_username})

		if user_data is None:
			logger.debug(f"User {username} does not exist")
			return False

		user_email = self.encryption.decrypt(user_data["email"])
		code = self.codes.create_code("recovery",hash_username)

		try:
			resend.Emails.send({
				"from": "send@frii.site",
				"to": user_email,
				"subject": "Password recovery",
				"html": recovery_template.replace("{{link}}",f"https://www.frii.site/account/recover?c={code}")
			})
		except resend.exceptions.ResendError as e:
			logger.error(f"Failed to send verification code {e.suggested_action}")
			return False

		logger.info(f"Sent password reset code to username {username}")
		return True
	