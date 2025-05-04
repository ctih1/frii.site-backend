import pytest
import os
from mock import MagicMock # type: ignore[import-untyped]
from dns_.validation import Validation
from dns_.dns import DNS
from database.exceptions import SubdomainError
from database.tables.domains import Domains
from database.tables.domains import Domains
import json

class TestDomainValidation:
    def test_valid_name(self):
        assert Validation.record_name_valid("example-domain","A")
    
    def test_invalid_name(self):
        assert not Validation.record_name_valid("Invälid_Recörd_Nämë", "A")

    def test_txt_record(self):
        assert Validation.record_name_valid("_verification", "TXT")
        
    def test_underscore_not_txt_record(self):
        assert not Validation.record_name_valid("_verification", "A")

    def test_valid_content(self):
        assert Validation.record_value_valid("1.2.3.4","A")
    
    def test_invalid_type(self):
        assert not Validation.record_value_valid("0.0.0.0","C")
    
    def test_invalid_content_for_type(self):
        assert not Validation.record_value_valid("test.cname.fi","A")
        
    def test_domain_clean(self):
        assert Domains.clean_domain_name("a.b") == "a[dot]b"
        assert Domains.beautify_domain_name(None,"a[dot]b") == "a.b"
        

    
    
domain_table: Domains =  MagicMock(spec=Domains)
dns: DNS = MagicMock(spec=DNS)

def domain_locator_side_effect(*args, **kwargs):
    if "domains.testing-domain" in list(args[0].keys())[0]:
        return {
            "testing-domains": {
                "id": "629dc7ce719cc5b852a86faa9183bbe60",
                "type": "A",
                "ip": "192.168.100.1",
                "registered": 1744103140.171228
            }
        }


domain_table.find_item.side_effect = domain_locator_side_effect # type: ignore[attr-defined]
domain_table.find_user.return_value = pytest.example_user # type: ignore[attr-defined]
        
class TestDomainUser:
    def test_domain_free(self):
        assert Validation(domain_table,dns).is_free("valid-domain","A",{},False)
        
    def test_domain_not_free(self):
        assert not Validation(domain_table,dns).is_free("testing-domains","A",{},False)
        
    def test_valid_subdomain(self):
        assert Validation(domain_table,dns).is_free("example.testing-domains","A",pytest.example_user["domains"])
        
    def test_invalid_subdomain(self):
        with pytest.raises(SubdomainError):
            Validation(domain_table,dns).is_free("example.not-owned","A",pytest.example_user["domains"])
