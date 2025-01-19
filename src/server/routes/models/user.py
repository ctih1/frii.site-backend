from pydantic import BaseModel
class SignUp(BaseModel):
    username:str
    password:str
    email:str
    language:str
    invite:str

class PasswordReset(BaseModel):
    code:str
    hashed_password:str