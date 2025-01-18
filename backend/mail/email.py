import os
import time
from typing import List, TYPE_CHECKING
import resend # type:ignore[import-untyped]
import resend.exceptions # type:ignore[import-untyped]
from security.encryption import Encryption
from debug.logger import Logger

if TYPE_CHECKING:
	from database.tables.codes import Codes
	from database.tables.general import General


template_path:str = os.path.join(".","mail","templates")

verify_template:str
recovery_template:str
deletion_template:str

with open(os.path.join(template_path,"verify.html"),"r") as f:
	verify_template = "\n".join(f.readlines())

with open(os.path.join(template_path,"deletion.html"),"r") as f:
	deletion_template = "\n".join(f.readlines())

with open(os.path.join(template_path,"recovery.html"),"r") as f:
	recovery_template = "\n".join(f.readlines())

l:Logger = Logger("email.py")

class Email:
	def __init__(self, codes:'Codes', general:'General'):
		self.table:Codes = codes
		self.general:General = general
		self.encryption:Encryption = Encryption(os.getenv("ENC_KEY"))
		resend.api_key = os.getenv("RESEND_KEY")

	def is_taken(self,email:str) -> bool:
		replaced_email:str = email.replace("+","@") # removes ability to make alt accounts using the same email (ex. a@gmail.com, a+hi@gmail.com)
		email_parts:List[str] = replaced_email.split("@")
		processed_email = f"{email_parts[0]}@{email_parts[-1]}"

		email_hash:str = Encryption.sha256(processed_email+"supahcool")

		print(self.table.find_item({"email-hash":email_hash}) )

		return self.table.find_item({"email-hash":email_hash}) is not None
	

	def send_verification_code(self,username:str, email:str) -> bool:
		code:str = self.table.create_code("verification",username)
		try:
			resend.Emails.send({
				"from": "send@frii.site",
				"to": email,
				"subject": "Verify your account",
				"html": verify_template.replace("{{link}}",f"https://www.frii.site/verify/{code}"),
				"text": f"Go to https://www.frii.site/verify/{code} to verify your account"
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
	
	def send_delete_code(self, username:str, email:str) -> bool:
		code:str = self.table.create_code("deletion",username)
		try:
			resend.Emails.send({
				"from": "send@frii.site",
				"to": email,
				"subject": "Account deletion",
				"html": deletion_template.replace("{{link}}",f"https://www.frii.site/verify/{code}"),
				"text": f"Go to https://www.frii.site/verify/{code} to verify your account"
			})
		except resend.exceptions.ResendError as e:
			l.error(f"Failed to send email to {email} error: {e}")
			return False
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
				"html": recovery_template.replace("{{link}}",f"https://www.frii.site/account/recover?c={code}")
			})
		except resend.exceptions.ResendError as e:
			l.error(f"Failed to send email to {username}, error {e}")
			return False
		
		return True
	