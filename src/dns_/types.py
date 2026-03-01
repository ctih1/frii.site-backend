from typing import Literal, TypedDict, List, get_args

AVAILABLE_TLDS = Literal["frii.site", "pill.ovh", "arr.ovh", "suomi.dev", "expect.ovh"]
TYPES = Literal["A", "AAAA", "CNAME", "TXT", "NS"]
ALLOWED_TYPES: List[str] = list(get_args(TYPES))

CHANGE_TYPE = Literal["REPLACE", "DELETE"]


class Record(TypedDict):
    content: str
    disabled: bool
    comment: str


class RRSet(TypedDict):
    name: str
    type: TYPES
    ttl: int
    changetype: CHANGE_TYPE
    records: List[Record]
