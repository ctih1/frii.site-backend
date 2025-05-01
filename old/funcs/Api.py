from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING
from hashlib import sha256
# pylint: disable=relative-beyond-top-level
from .Utils import generate_random_string
from .Session import Session
if TYPE_CHECKING:
    from Database import Database

class Permission(Enum): # sorry
    M_TYPE=0
    M_DOMAIN=1
    M_CONTENT=2
    DELETE=3
    DETAILS=4
    CREATE=5

class ApiKeyError(Exception):
    pass

class Api:
    @staticmethod
    def find_api_instance(args:tuple, kwargs:dict) -> Api:
        """Finds session from args or kwargs.
        """
        target: Api = None
        if kwargs.get("api") is not None:
            target = kwargs.get("api")  # type: ignore
        else:
            for arg in args:
                if type(arg) is Api:
                    target = arg
        return target

    @staticmethod
    def requires_auth(func):
        """
        Same as Session.requires_auth, but uses `api` as the key instead of `session`
        """

        def inner(*args, **kwargs):
            target: Api = Api.find_api_instance(args,kwargs)
            if not target.valid:
                raise ApiKeyError("Session is not valid")
            a = func(*args, **kwargs)
            return a
        return inner

    @staticmethod
    def create(session:Session, permissions_: list, domains: list, comment: str, database:Database) -> str:
        """Creates an API Key

        Args:
            permissions_ (list): list of permissions [view content type domain delete]
            domains (list): list of domains that this will affect
            comment (str): Users left comment
            database (Database): instance of database
        Raises:
        Returns:
            str: API Key
        """
        api_key:str="$APIV1="+generate_random_string(32)
        user_domains = database.get_data(session).get("domains",{})
        for domain in domains:
            if(domain not in list(user_domains.keys())):
                raise PermissionError("User does not own domain")

        key = {
            "string": database.fernet.encrypt(bytes(api_key,'utf-8')).decode(encoding='utf-8'),
            "perms":permissions_,
            "domains":domains,
            "comment":comment
        }

        encrypted_api_key:str = sha256((api_key+"frii.site").encode("utf-8")).hexdigest()
        database.collection.update_one({"_id":session.username},{"$set":{f"api-keys.{encrypted_api_key}":key}})
        database.modify_cache(session.username,f"api-keys.{encrypted_api_key}", key)
        return api_key

    def __init__(self,key:str,database:Database)->None:
        self.key:str=key
        self.perms_class = Permission
        self.db=database
        self.__search_key = sha256((self.key+"frii.site").encode("utf-8")).hexdigest() # frii.site used for salting
        self.valid=True
        try:
            self.permissions=self.__get_perms()
        except IndexError:
            self.valid = False
        self.username=self.__get_username()
        self.domains=self.__get_domains() # domains owned by user
        self.affected_domains = self.__get_affected_domains() # domains that the API can modify

    def get_domain_id(self,target:str) -> str:
        return self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}}).get("domains",{}).get(target,{}).get("id")

    def has_permission(self,target:Permission,domain:str, domains:list) -> bool:
        """Checks if API key has permissions to do a certain task

        Args:
            target (Permission): Permission required
            domain (str): Domain that is trying to be modified

        Returns:
            bool: if has
        """
        if domain not in domains: return False
        return target in self.permissions

    def required_permissions(self,domain:str,type_:str,content:str) -> list[Permission]:
        """Gives a list of required permissions

        Args:
            domain (str): domain affected
            type_ (str): domain type
            content (str): domain content

        Returns:
            list[Permission]: list of permissions
        """
        needed_perms:list[Permission] = []
        target_domain = self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}}).get("domains",{}).get(domain,{})
        print("Target domain: "+str(target_domain))
        if(target_domain.get("type")!=type_):
            needed_perms.append(Permission.M_TYPE)
        if(target_domain.get("ip")!=content):
            needed_perms.append(Permission.M_CONTENT)
        print("Needed perms: "+ str(needed_perms))
        return needed_perms

    def __get_perms(self) -> list:
        result = self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}})
        permissions:list = result.get("api-keys",{}).get(self.__search_key,{}).get("perms")
        permissions_list:list = []
        for permission in permissions:
            # pylint: disable=multiple-statements
            if(permission=="view"):  permissions_list.append(Permission.DETAILS)
            if(permission=="content"):  permissions_list.append(Permission.M_CONTENT)
            if(permission=="domain"):  permissions_list.append(Permission.M_DOMAIN)
            if(permission=="type"):  permissions_list.append(Permission.M_TYPE)
            if(permission=="delete"):  permissions_list.append(Permission.DELETE)
            if(permission=="create"): permissions_list.append(Permission.CREATE)
        return permissions_list

    @Session.requires_auth
    def delete(self,session:Session) -> bool:
        self.db.collection.update_one({f"api-keys.{self.__search_key}":{"$exists":True}},{"$unset":{f"api-keys.{self.__search_key}":""}})
        return True

    def __get_domains(self) -> list:
        result = self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}})
        return result.get("domains",[])

    def __get_username(self) -> str:
        return self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}}).get("_id")

    def __get_affected_domains(self) -> list:
        return self.db.collection.find_one({f"api-keys.{self.__search_key}":{"$exists":True}}).get("api-keys",{}).get(self.__search_key,{}).get("domains")
    @staticmethod
    @Session.requires_auth
    def get_keys(session:Session,db:Database) -> list:
        """Returns the users api keys
        Returns:
            `[{key:string, domains:string[], perms:string[], comment:string}]`
        """
        user_keys:list = []
        keys = db.get_data(session).get("api-keys",{})
        for key in keys:
            api_key = db.fernet.decrypt(str.encode(keys[key]["string"])).decode("utf-8")
            user_keys.append({"key":api_key,"domains":keys[key]["domains"], "perms":keys[key]["perms"], "comment":keys[key]["comment"]})
        return user_keys
