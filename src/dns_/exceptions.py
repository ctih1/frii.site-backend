class DNSException(Exception):
    def __init__(
        self, message: str, json: dict | None = None, type_: str | None = None
    ):
        self.json = json
        self.type_ = type_  # meant for invalid types
        super().__init__(message)


class DomainExistsError(Exception): ...
