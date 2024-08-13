from .Database import Database
from .Token import Token

DOMAIN_PRICE = 200

class Credits:
    def __init__(self,db:Database):
        self.db:Database = db
    
    def convert(self,token:Token):
        if(not token.password_correct(self.db)): raise PermissionError("Invalid token")
        __data=self.db.get_data(token)
        credits = __data.get("credits",0)
        max_domains = __data["permissions"].get("max-domains",4)
        if(not __data.get("feature-flags",{}).get("credits",False)): raise PermissionError("Not a beta tester")
        if(credits<DOMAIN_PRICE): raise AttributeError("Not enough credits")
        self.db.update_data(token.username,"credits",credits-DOMAIN_PRICE)
        self.db.update_data(token.username,"permissions.max-domains",max_domains+1)
        self.db.remove_from_cache(token)
        return True
    
    def get(self,token:Token) -> int:
        __data=self.db.get_data(token)
        if(not __data.get("feature-flags",{}).get("credits",False)): raise PermissionError("Not a beta tester")
        return __data.get("credits",0)