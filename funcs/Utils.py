import random
import string

def generate_password(length: int) -> str:
  """
  Returns a random password THAT ISNT ENCRYPTED.
  """
  return ''.join(random.choice(string.printable) for i in range(length)) # just some random characters. not encrypted. I have no idea what this is used for

def generate_random_pin(lenght: int) -> str:
  raise DeprecationWarning("This method should no longer be used, please use 'generate_random_string(length:int)'")
  return str(''.join(random.choice(string.digits) for i in range(lenght)))

def generate_random_string(lenght:int) -> str:
  return str(''.join(random.choice(string.ascii_letters+string.digits) for i in range(lenght)))

def days_to_seconds(days:int) -> int:
    return ((days*24)*60)*60

class CredentialError(Exception):
  def __init__(self,message,errors):
    super().__init__(message)
    self.errors=errors
