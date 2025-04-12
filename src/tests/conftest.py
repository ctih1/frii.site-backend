import pytest
import os
import json
from database.tables.users import UserType

def load_user() -> UserType:
    example_normal = {}
    with open(os.path.join(".","src","tests","example-data","user.json"),"r") as f:
        example_normal = json.load(f)
        
    return example_normal # type: ignore[return-value]
 
def pytest_configure():
    pytest.example_user = load_user()