class DNSException(Exception):
    def __init__(self, message:str, json:dict):
        self.json = json
        super().__init__(message)