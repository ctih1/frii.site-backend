from .Database import Database
from .Session import Session

DOMAIN_PRICE = 200

class Credits:
    def __init__(self,db:Database):
        self.db:Database = db

    @Session.requires_auth
    @Session.requires_flag("credits")
    def convert(self,session:Session):
        __data=self.db.get_data(session)
        credits = __data.get("credits",0)
        max_domains = __data.get("permissions").get("max-domains")
        if(credits<DOMAIN_PRICE): raise AttributeError("Not enough credits")
        self.db.update_data(session.username,"credits",credits-DOMAIN_PRICE)
        self.db.update_data(session.username,"permissions.max-domains",max_domains+1)
        self.db.remove_from_cache(session.username)
        return True

    def get(self,session:Session) -> int:
        __data=self.db.get_data(session)
        if(not __data.get("feature-flags",{}).get("credits",False)): raise PermissionError("Not a beta tester")
        return __data.get("credits",0)
