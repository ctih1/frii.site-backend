class InviteException(Exception):
    pass

class EmailException(Exception):
    pass

class UsernameException(Exception):
    pass

class UserNotExistError(Exception):
    pass

class FilterMatchError(Exception):
    pass
class SubdomainError(Exception):
    def __init__(self, message:str, required_domain:str):
        self.required_domain:str = required_domain
        super().__init__(message)