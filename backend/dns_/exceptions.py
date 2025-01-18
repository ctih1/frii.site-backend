class DNSException(Exception):
    def __init__(self, message:str, json:dict, type_:str=None):
        self.json = json
        self.type_ = type_ # meant for invalid types
        super().__init__(message)

class DomainExistsError(Exception): ...