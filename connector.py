import bcrypt
from funcs import Admin, Database as _Database
from funcs import Domain as _Domain
from funcs import Email as _Email
from funcs import Session as _Session
from  funcs.Utils import *  # noqa: F403
from funcs import Vulnerability as _Vulnerability
from funcs import Translations as _Translations
from funcs import Api as _Api
from funcs import Blog as _Blog
from flask import Response, render_template
from funcs import Logger as _Logger
from funcs import Credits as _Credits
from funcs import Admin as _Admin
import os
from dotenv import load_dotenv
import json
import time
from hashlib import sha256

Database = _Database.Database
Domain = _Domain.Domain
Email = _Email.Email
Api = _Api.Api
Credits = _Credits.Credits
Vulnerability = _Vulnerability.Vulnerability
Admin = _Admin.Admin
Session = _Session.Session
load_dotenv()

database:Database = Database(os.getenv("MONGODB_URL"),os.getenv("ENC_KEY"))
api:Api
domain:Domain = Domain(database,os.getenv("EMAIL"),os.getenv("CF_KEY_W"),os.getenv("CF_KEY_R"),os.getenv("ZONEID"))
email:Email = Email(os.getenv("RESEND_KEY"),database)
vulnerability:Vulnerability = Vulnerability(database)
blog:_Blog.Blog = _Blog.Blog(database)

credits = Credits(database)
translations = None
l = _Logger.Logger("connector.py", os.getenv("DC_WEBHOOK"),os.getenv("DC_TRACE"))


def login(username_hash:str, password_hash:str, ip:str, user_agent:str) -> Response:
    data = database.collection.find_one({"_id":username_hash})
    db_password = data["password"].encode("utf-8")

    if not bcrypt.checkpw(password_hash.encode("utf-8"),db_password): return Response(status=401)
    if not data.get("verified",False): return Response(status=412)

    session_create_status:_Session.SessionCreateStatus = Session.create(username_hash,ip,user_agent, database)
    if session_create_status["mfa_required"]:
        return Response(status=403)
    elif not session_create_status["success"]:
        return Response(status=500)

    return Response(status=200, response=session_create_status["code"])

#/sign-up
def sign_up(username:str,password:str,email_:str,language:str,country:str) -> Response:
    return Response(status=403, response="Account registration has been disabled.")
    status:dict = database.create_user(username,password,email_,language,country,time.time(),email)
    responses = {
        1001: 409,
        1002: 400,
        1003: 422
    }
    if status.get("Error",False):
        return Response(status=responses.get(status["code"]),response=json.dumps(status.get("message","No extra information provided")))
    return Response(status=200)

#/domain-is-available
def domain_is_available(__domain:str) -> Response:
    __domain = __domain.replace(".","[dot]")
    domain_status: int = domain.check_domain(__domain)
    # vercel uses python 3.9, thus why there is no switch case logic.
    responses:dict= {
        1:200,
        0:400,
        -1:401,
        -2:409
    }
    return Response(status=responses.get(domain_status))

#/register-domain
def register_domain(__domain:str,content:str,token_:str,type_:str, proxy:bool, request_ip) -> Response:
    __domain = __domain.replace(".","[dot]")
    if(token_.startswith("$API")):
        status = domain.register_with_api(__domain,content,Api(token_,database),type_)
        return Response(status=200, response=json.dumps(status), mimetype="application/json")
    else:
        session = Session(token_,request_ip,database)
        domain_register_status: dict = domain.register(domain=__domain,content=content,session=session,type_=type_,proxied=proxy)
        responses:dict = {
            1000: 401,
            1001: 400,
            1002: 403,
            1003: 429,
            1004: 406,
            1014: 405, # does not own a certain part of the domain
            1024: 409 # domain in use
        }
        if(domain_register_status.get("Error",False)):
            return Response(status=responses.get(domain_register_status["code"],500),response=json.dumps(domain_register_status.get("message","No extra information given")))
        return Response(status=200)

#/modify-domain
def modify_domain(__domain:str, token:str, content:str, type_:str, proxied:bool, request_ip) -> Response:
    __domain = __domain.replace(".","[dot]")
    if(token.startswith("$API")):
        status = domain.modify_with_api(database,__domain,Api(token,database),content,type_)
        responses: dict = {
            1000: 200,
            1001: 403,
            1002: 422,
            1003: 500
        }
        return Response(status=responses.get(status["code"]),response=status.get("message","No extra information"))
    else:
        session = Session(token,request_ip,database)
        status = domain.modify(database=database,domain=__domain,session=session,new_content=content,type_=type_,proxied=proxied)
        response:dict = {
            1001: 406,
            1011: 405,
            1021: 409,
            1004: 401,
            1005: 403
        }
        if(status.get("Error",False)):
            return Response(status=response.get(status["code"]),response=status.get("message","No extra information"))
        return Response(status=200)

#/verification/<string:Code>
def verification(code:str) -> Response:
    if(email.verify_email(code)):
        return render_template("verify.html",status="Succesfully verified!",status_message="Your account has succefully been verified. Feel free to close this tab and return to your previous one.")
    else:
        return render_template("verify.html",status="Failed to verify",status_message="Failed to verify your account. Perhaps the code has expired?")

#/gpdr-get
def gpdr_get(token:str, ip) -> Response:
    status = database.get_gpdr(session=Session(token,ip,database))
    if(status.get("Error",False)):
        return Response(status=401)
    return Response(response=json.dumps(status),status=200,mimetype="application/json")

#/get-user-info
def get_user_info(token, ip) -> Response:
    responses = {
        1001: 401
    }
    status:dict = database.get_basic_user_data(session=Session(token, ip, database))
    if("Error" in status): return Response(status=responses.get(status["code"]))
    return Response(response=json.dumps(status),status=200,mimetype="application/json")

#/get-domains
def get_domains(token:str, ip) -> Response:
    status_:dict = domain.get_user_domains(database=database,session=Session(token, ip, database))
    if("Error" in status_):
        if(status_["code"] == 1002): rs = 404
        else: rs = 401
        return Response(status=rs)
    return Response(response=json.dumps(status_),status=200,mimetype="application/json")

#/delete-domain
def delete_domain(token:str,domain_:str, ip) -> Response:
    domain_ = domain_.replace(".","[dot]")

    responses = {
        -1: 403,
        0: 401,
        1: 200
    }
    status:int = domain.delete_domain(session=Session(token, ip, database),domain=domain_)
    return Response(status=responses.get(status))

#/delete-user
def delete_user(token:str, ip) -> Response:
    """Doesn't acutally delete the user, just sends an email with a verification code
    """
    session = Session(token, ip, database)
    user_data=database.get_basic_user_data(session)
    if(email.send_delete_email(email=user_data["email"],session=session,displayname=user_data["username"])):
        return Response(status=200)
    return Response(status=401)

#/account-deletion<string:Code>
def account_deletion(code:str, ip) -> Response:
    status:int = email.delete_user(code,domain, ip)
    responses = {
        1001: 422,
        1002: 410
    }
    if(status.get("Error",False)):
        return Response(status=responses.get(status["code"]))
    return Response(status=200)

#/resend-email
def resend_email(username:str) -> Response:
    if(email.resend_email(username)): return Response(status=200)
    return Response(status=401)

#/vulnerability/report
def vulnerability_report(endpoint:str,email:str,expected:str,actual:str,importance:str,description:str,steps:str,impact:str,attacker:str) -> Response:
    status:str = vulnerability.create(endpoint,email,expected,actual,importance,description,steps,impact,attacker)
    return Response(response=json.dumps({"code":status}),status=200,mimetype="application/json")

#/vulnerability/get
def vulnerability_get(id:str) -> Response:
    status:dict
    try:
        status = vulnerability.get_report(id)
    except(ValueError):
        return Response(response=json.dumps({"Error":True,"code":1001,"message":"No report found"}), status=404, mimetype="application/json")
    return Response(response=json.dumps(status),status=200,mimetype="application/json")

#/vulnerability/progress
def vulnerability_progress(id:str,progress:str,time:int,token:str, ip) -> Response:
    status:int = vulnerability.report_progress(id=id,progress=progress,time=time,session=(token,ip,database))
    if(not status):
        return Response(status=403)
    return Response(status=200)

def vulnerability_status(id:str,status:str,mode:str,d_importance:int,token:str,ip) -> Response:
    statuses = {
        1: 200,
        0: 422,
        -1: 403
    }
    status = vulnerability.report_status(id=id,status=status,mode=mode,importance=d_importance,session=Session(token,ip,database))
    return Response(status=statuses.get(status))

#/vulnerability/all
def vulnerability_all(token:str, ip):
    try:
        status = vulnerability.get_reports(session=Session(token, ip, database))
    except PermissionError:
        status = {"Error":True,"message":"Token does not have permissions to access this."}

    return Response(status=200,response=json.dumps(status))

#/create-api
def create_api(token:str,domains:list,permissions:list,comment:str, ip) -> Response:
    try:
        status = Api.create(session=Session(token,ip,database),permissions_=permissions,domains=domains,comment=comment,database=database)
    except PermissionError:
        return Response(status=403)
    return Response(status=200, response=status)

#/admin/get-email
def admin_get_email(token:str,id:str, ip) -> Response:
    status = database.admin_get_basic_data(session=Session(token, ip, database),id=id)
    if(status.get("Error")):
        return Response(status=401,response="You don't have permissions to use this.")
    return Response(status=200,response=json.dumps(status),mimetype="application/json")

def admin_get_emails(token:str,condition:dict, ip) -> Response:
    status = database.admin_get_emails(session=Session(token,ip, database),condition=condition)
    if(status.get("Error")):
        return Response(status=401,response="You don't have permissions to use this.")
    return Response(status=200,response=json.dumps(status),mimetype="application/json")

def reset_password(username:str) -> Response:
    status = email.initiate_recovery(username)
    return Response(status=200,response=json.dumps({"Error": not status}))

def account_recovery(code:str,password:str) -> Response:
    status = email.reset_password(code,password)
    return Response(status=200, response=json.dumps({"Error":not status}),mimetype="application/json")

def join_beta(token:str, ip) -> Response:
    if(database.join_beta(session=Session(token, ip, database))): return Response(status=200)
    return Response(status=401)

def leave_beta(token:str,ip) -> Response:
    if(database.leave_beta(session=Session(token,ip,database))): return Response(status=200)
    return Response(status=401)

def __init_translations():
    global translations
    if(translations is None): translations = _Translations.Translations(os.getenv("GH_KEY"),database)


def translation_percentages():
    __init_translations()
    return Response(status=200,response=json.dumps(translations.get_percentages()),mimetype="application/json")

def translation_missing(country:str) -> Response:
    __init_translations()
    return Response(status=200, response=json.dumps(translations.get_keys(country)),mimetype="application/json")

def translation_contribute(token:str,lang:str,contributions:list, ip) -> Response:
    __init_translations()
    if(translations.contribute(lang=lang,keys=contributions,session=Session(token,ip,database))): return Response(status=200)
    return Response(status=401)

#/credits/cover POST
def credits_convert(token:str, ip) -> Response:
    try:
        status = credits.convert(session=Session(token,ip, database))
    except PermissionError:
        return Response(status=401,response="Invalid token",mimetype="text/plain")
    except AttributeError:
        return Response(status=403,response="Not enough credits",mimetype="text/plain")
    return Response(status=200)

def status() -> Response:
    status = database.get_status()
    if(status.get("reports",True)):
        return Response(status=200,response=status.get("message","Our servers are experiencing issues."), mimetype="text/plain")
    return Response(status=204)

def credits_get(token:str, ip) -> Response:
    try:
        status = credits.get(session=Session(token,ip,database))
    except PermissionError:
        return Response(status=403)
    return Response(status=200,response=json.dumps({"credits":status}), mimetype="application/json")

def blog_get(blog_:str) -> Response:
    try:
        status = blog.get(blog_)
        return Response(status=200,response=json.dumps(status),mimetype="application/json", headers={"Cache-Control":"public,max-age=0, s-maxage=1209600","Access-Control-Allow-Origin": "*"})
    except KeyError:
        return Response(status=404)

def blog_create(auth:str,title:str,body:str,ip:str,url=None) -> Response:
    try:
        status = blog.create(session=Session(auth,ip,database),title=title,body=body,url=url)
    except CredentialError:
        return Response(status=403)
    except PermissionError:
        return Response(status=401)
    return Response(status=200)

def get_api_keys(auth:str, ip) -> Response:
    auth_token = Session(auth, ip, database)
    return Response(status=200,response=json.dumps(Api.get_keys(session=auth_token,db=database)),mimetype="application/json")

def api_delete(auth:str,key:str, ip) -> Response:
    auth_token = Session(auth, ip, database)
    try:
        Api(key,database).delete(session=auth_token)
    except PermissionError:
        return Response(status=403)
    return Response(status=200)

def blog_get_all(n:int,content:int=0) -> Response:
    try:
        l.info(f"blog_get_all content={content}")
        blogs = blog.get_list(n,content)
    except ValueError as e:
        l.warn(f"ValueError while runniing blog.get_list(), aborting. {e}")
        return Response(status=412)
    return Response(status=200,response=json.dumps(blogs), mimetype="application/json", headers={"Cache-Control":"public,max-age=0, s-maxage=1800","Access-Control-Allow-Origin": "*"})

def get_active_sessions(session_id:str, ip:str) -> Response:
    return Response(status=200, mimetype="application/json", response=json.dumps(Session(session_id, ip, database).get_active()))

def create_2fa(session_id:str, ip:str) -> Response:
    session = Session(session_id,ip,database)
    code = session.create_2fa()
    return Response(status=200, mimetype="text/plain", response=code)

def verify_2fa(userid, code:str):
    if(Session.verify_2fa(code,userid,database)) == True:
        return Response(status=200)
    else:
        return Response(status=401)

def delete_session(session_id, ip:str, session) -> Response:
    return Response(status=200, response=str(Session(session_id,ip,database).delete(session)))

def logout_session(session_id, ip:str) -> Response:
    Session(session_id, ip,database).delete(sha256(session_id.encode("utf-8")).hexdigest())
    return Response(
        status=200,

    )
