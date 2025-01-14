import unittest
from dotenv import load_dotenv
from funcs import Database as _db
from funcs import Token as _Token
from funcs import Domain as _Domain
from funcs import Vulnerability as _Vulnerability
from funcs import Utils
from funcs import Email as _Email
from funcs import Logger as _Logger
import os

load_dotenv()

db = _db.Database
database = db(os.getenv("MONGODB_URL"),os.getenv("ENC_KEY"))
Token = _Token.Token
Domain = _Domain.Domain
Email = _Email.Email
Vulnerability = _Vulnerability.Vulnerability
domain = Domain(database,os.getenv("EMAIL"),os.getenv("CF_KEY_W"),os.getenv("CF_KEY_R"),os.getenv("ZONEID"))
timestamp=1000000000
class Test(unittest.TestCase):
    def test_domain_lookup(self):
        with self.subTest("Looking for domain existance - true"):
            self.assertEqual(database.check_database_for_domain("unittest"),True)
        with self.subTest("Looking for domain existance - false"):
            self.assertEqual(database.check_database_for_domain(",.-"),False)
    def test_token(self):
        with self.subTest("Seeing if correct account- valid"):
            token:Token = Token(str(os.getenv("TESTING_ACCOUNT")))
            self.assertTrue(token.password_correct(database))
        with self.subTest("Seeing if correct account - invalid"):
            token:Token = Token(str(os.getenv("TESTING_ACCOUNT"))+"abcd")
            self.assertFalse(token.password_correct(database))
    def test_domain_allowed(self):
        with self.subTest("Testing if domain is valid - invalid"):
            self.assertFalse(Domain.is_domain_valid("imake$$$"))
        with self.subTest("Testing if domain is valid - valid"):
            self.assertTrue(Domain.is_domain_valid("testing-my-website"))
    def test_domain_modification(self):
        random_code = Utils.generate_random_string(12)
        with self.subTest("Modifying domain"):
            self.assertEqual(domain.modify(database,"unittest",Token(str(os.getenv("TESTING_ACCOUNT"))),random_code,"TXT"),{"Error":False,"message":"Succesfully modified domain"})
        with self.subTest("Seeing if domain content changed"):
            self.assertEqual(domain.get_user_domains(database,Token(str(os.getenv("TESTING_ACCOUNT")))).get("unittest",{}).get("ip"),random_code)
    def test_domain_registration(self):
        random_domain=Utils.generate_random_string(32)
        random_content=Utils.generate_random_string(32)
        with self.subTest("Creating a new testing domain"):
            self.assertEqual(domain.register(random_domain,random_content,Token(str(os.getenv("TESTING_ACCOUNT"))),"TXT"),{"Error":False,"message":"Succesfully registered"})
        with self.subTest("Seeing if domain exists"):
            self.assertEqual(domain.get_user_domains(database,Token(str(os.getenv("TESTING_ACCOUNT")))).get(random_domain,{}).get("ip"),random_content)
        with self.subTest("Deleting domain"):
            token=Token(str(os.getenv("TESTING_ACCOUNT")))
            self.assertEqual(domain.delete_domain(token,random_domain),1)
        with self.subTest("Seeing if domain exists"):
            self.assertEqual(domain.get_user_domains(database,Token(os.getenv("TESTING_ACCOUNT"))).get(random_domain,None),None)
        with self.subTest("Not allowing subdomain"):
            self.assertEqual(domain.register("testing.testing.frii.site",random_content,Token(str(os.getenv("TESTING_ACCOUNT"))),"TXT"),{"Error":True,"code":1014,"message":"Domain is not valid. Reason No. -1"})
    def vulnerability_reporting(self):
        vuln:Vulnerability = Vulnerability(database)
        report_id:str
        with self.subTest("Creating a new vuln report"):
            report_id=vuln.create("endpoint","email","expected","actual",0,"description","steps","impact","attacker")
            self.assertIsNotNone(report_id)
        with self.subTest("Get report - valid"):
            report_result = vuln.get_report(report_id)
            self.assertIsNotNone(report_result)
            self.assertDictEqual(
                {"endpoint":"endpoint","email":"email","expected":"expected","actual":"actual","description":"description","steps":"steps","impact":"impact","attacker":"attacker"},
                {"endpoint":report_result["endpoint"],"email":report_result["email"],"expected":report_result["expected"],"actual":report_result["actual"],"description":report_result["description"],"steps":report_result["steps"],"impact":report_result["impact"],"attacker":report_result["attacker"]}
            )
        with self.subTest("Get report - invalid"):
            self.assertRaises(ValueError,vuln.get_report,"x")
        with self.subTest("Updating report progress - permissions"):
            self.assertTrue(vuln.report_progress(report_id,"unittest",timestamp,Token(os.getenv("TESTING_ACCOUNT")))) # testing account has permissions
        with self.subTest("Updating report progress - no permissions"):
            self.assertFalse(vuln.report_progress(report_id,"unittest",timestamp,Token(os.getenv("HACKER_ACCOUNT")))) # no permissin
        with self.subTest("Updating report steps"):
            self.assertEqual(vuln.report_status(report_id,"seen",True,-1,Token(os.getenv("TESTING_ACCOUNT"))),1)
        with self.subTest("Marking report as done"):
            self.assertTrue(vuln.mark_as_solved(report_id,Token(os.getenv("TESTING_ACCOUNT"))))
        with self.subTest("Checking report progress"):
            report_status = vuln.get_report(report_id)
            self.assertEqual(type(report_status),dict)
            self.assertTrue(report_status["progress"]["steps"]["seen"])
            self.assertIn({"unittest":timestamp},report_status["progress"]["progress"])
            self.assertTrue(report_status["solved"])
        with self.subTest("Deleting report"):
            self.assertTrue(vuln.delete_report(report_id,Token(os.getenv("TESTING_ACCOUNT"))))
        with self.subTest("Checking if report deleted"):
            self.assertRaises(ValueError,vuln.get_report,report_id)
if(__name__=="__main__"):
    unittest.main(argv=["ignored","-v"])
    