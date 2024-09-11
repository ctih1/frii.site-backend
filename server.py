from flask import Flask, request, jsonify, url_for
from flask import render_template
from connector import *
import ipinfo
import os
from flask_cors import CORS, cross_origin
import time
from flask_limit import RateLimiter
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
limiter = RateLimiter(app)
CORS(app)
handler = ipinfo.getHandler(os.getenv('IPINFO_KEY'))

@app.errorhandler(AssertionError)
def handle_assert_error(error):
  return Response(status=403,response="Invalid token",mimetype="text/plain")

@app.route("/")
@cross_origin()
def index():
  return "OK",200

@app.route('/login', methods=['POST'])
def login_():
  return login(request.headers.get("X-Auth-Token"))

@limiter.rate_limit(limit=1,period=120*60)
@app.route('/sign-up', methods=['POST'])
def sign_up_():
  username = request.json.get('username')
  password = request.json.get('password')
  email = request.json.get('email')
  language = request.json.get('language')
  country = handler.getDetails(request.access_route[-1]).all
  return sign_up(
    username,
    password,
    email,
    language,
    country,
  )

@app.route('/domain-is-available',methods=["GET"])
@limiter.rate_limit(limit=50,period=300)
def domain_is_available_():
  domain_ = request.args.get("domain",None)
  return domain_is_available(domain_)

@app.route("/register-domain",methods=["POST"])
@limiter.rate_limit(limit=9,period=10800)
def register_domain_():
  domain_ = request.json.get("domain")
  token_ = request.headers.get("X-Auth-Token",request.headers.get("X-Api-Key"))
  ip = request.json.get("content")
  type_ = request.json.get("type")
  proxied = request.json.get("proxy",False)
  return register_domain(domain_,ip,token_,type_, proxied)

@app.route("/modify-domain",methods=["PATCH"])
@limiter.rate_limit(limit=12,period=10*60)
def modify_domain_():
  domain_ = request.json.get("domain")
  token_ = request.headers.get("X-Auth-Token",request.headers.get("X-Api-Key"))
  content = request.json.get("content")
  type_ = request.json.get("type")
  proxied = request.json.get("proxy",False)
  return modify_domain(domain_,token_,content,type_,proxied)

@limiter.rate_limit(limit=5,period=15*60)
@app.route("/verification/<string:Code>", methods=["GET"])
def verification_(Code):
  return verification(Code)

@limiter.rate_limit(limit=2,period=30*60)
@app.route("/gdpr-get",methods=["GET"])
def gpdr_get_():
  token_=request.headers.get("X-Auth-Token")
  return gpdr_get(token_)

@limiter.rate_limit(limit=12,period=60)
@app.route("/get-user-info",methods=["GET"])
def get_user_info_():
  token_ = request.headers.get("X-Auth-Token")
  return get_user_info(token_)

@limiter.rate_limit(limit=25,period=3*60)
@app.route("/get-domains", methods=["GET"])
def get_domains_():
  token_ = request.headers.get("X-Auth-Token")
  return get_domains(token_)

@limiter.rate_limit(limit=9,period=120)
@app.route("/is-verified", methods=["GET"])
def is_verified_():
  token_ = request.headers.get("X-Auth-Token")
  return is_verified(token_)

@limiter.rate_limit(limit=9,period=120)
@app.route("/delete-domain",methods=["DELETE"])
def delete_domain_():
  token = request.headers.get("X-Auth-Token")
  domain = request.json.get("domain")
  return delete_domain(token, domain)

@limiter.rate_limit(limit=3,period=10*60)
@app.route("/delete-user",methods=["DELETE"])
def delete_user_():
  token_ = request.headers.get("X-Auth-Token")
  return delete_user(token_)

@app.route("/account-deletion/<string:Code>")
def account_deletion_(Code):
  return account_deletion(Code)

@limiter.rate_limit(limit=1,period=30)
@app.route("/resend-email", methods=["GET"])
def resend_email_():
  return resend_email(request.headers.get("X-Auth-Token"))

@limiter.rate_limit(limit=3, period=120*60)
@app.route("/vulnerability/report", methods=["POST"])
def vulnerability_report_():
  rj=request.json
  return(vulnerability_report(rj.get("endpoint"),rj.get("contact-email"),rj.get("expected"),rj.get("actual"),rj.get("importance"),rj.get("description"),rj.get("steps"),rj.get("impact"),rj.get("attacker")))

@app.route("/vulnerability/get", methods=["GET"])
def vulnerability_get_():
  return vulnerability_get(request.args.get("id"))

@app.route("/vulnerability/progress",methods=["PATCH"])
def add_progress():
  return vulnerability_progress(request.json.get("id"),request.json.get("progress"),request.json.get("time"),request.headers.get("X-Auth-Token"))

@app.route("/vulnerability/status",methods=["PATCH"])
def update_status():
  return vulnerability_status(request.json.get("id"),request.json.get("status"),request.json.get("mode"),request.json.get("d-importance"),request.headers.get("X-Auth-Token"))

@app.route("/vulnerability/all",methods=["GET"])
def get_all():
  return vulnerability_all(request.headers.get("X-Auth-Token"))

@app.route("/vulnerability/solve",methods=["PUT"])
def solve():
  return mark_as_solved(request.json.get("id"),request.headers.get("X-Auth-Token"))

@app.route("/vulnerability/delete",methods=["POST"])
def delete_vuln():
  return delete_report(request.json.get("id"),request.headers.get("X-Auth-Token"))

@app.route("/create-api",methods=["POST"])
def create_api_():
  return create_api(request.headers.get("X-Auth-Token"),request.json.get("domains"),request.json.get("perms"),request.json.get("comment"))

@app.route("/get-api-keys",methods=["GET"])
def get_api_keys_():
  return get_api_keys(request.headers.get("X-Auth-Token"))

@app.route("/admin/get-email",methods=["GET"])
def admin_get_email_():
  return admin_get_email(request.headers.get("X-Auth-Token"),request.args.get("id"))

@app.route("/admin/get-emails",methods=["POST"])
def admin_get_emails_():
  return admin_get_emails(request.headers.get("X-Auth-Token"),request.json.get("condition"))

@app.route("/reset-password",methods=["PATCH"])
def reset_password_():
  return reset_password(request.json.get("username"))

@app.route("/account-recovery/<string:Code>", methods=["PATCH"])
def account_recovery_(Code):
  return account_recovery(Code,request.json.get("password"))

@app.route("/join/beta",methods=["POST"])
def join_beta_():
  return join_beta(request.headers.get("X-Auth-Token"))

@app.route("/leave/beta",methods=["POST"])
def leave_beta_():
  return leave_beta(request.headers.get("X-Auth-Token"))

@app.route("/translation/percentages",methods=["GET"])
def translation_percentages_():
  return translation_percentages()

@app.route("/translation/<string:Code>/missing", methods=["GET"])
def translation_missing_(Code):
  return translation_missing(Code)

@app.route("/translations/<string:Code>/contribute",methods=["POST"])
def translation_contribute_(Code):
  return translation_contribute(request.headers.get("X-Auth-Token"),Code,request.json.get("contributions"))

@app.route("/credits/convert",methods=["POST"])
def credits_convert_():
  return credits_convert(request.headers.get("X-Auth-Token"))

@app.route("/credits/get",methods=["GET"])
def credits_get_():
  return credits_get(request.headers.get("X-Auth-Token"))

@app.route("/status", methods=["GET"])
def status_():
  return status()

@app.route("/blog/<string:Blog>",methods=["GET"])
def blog_get_(Blog:str):
    return blog_get(Blog)

@app.route("/blog/create", methods=["POST"])
def blog_create_():
    return blog_create(request.headers.get("X-Auth-Token"),request.json.get("title"), request.json.get("body"), request.json.get("url"))

if(__name__=="__main__"):
  app.run(port=5000,debug=True)
