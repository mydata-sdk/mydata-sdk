# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import time
from json import loads, dumps

from flask import request, Blueprint, current_app, render_template_string, make_response, redirect
from flask_cors import CORS
from flask_restful import Resource, Api, reqparse
from jwcrypto import jwk
from requests import post

from base64 import urlsafe_b64encode as encode64
from base64 import urlsafe_b64decode as decode64

from uuid import uuid4 as guid
from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_mock import Helpers, api_logging
from Templates import users

debug_log = logging.getLogger("debug")

api_Root_blueprint = Blueprint("api_ServiceMockup_Service", __name__)  # TODO Rename better

CORS(api_Root_blueprint)
api = Api()
api.init_app(api_Root_blueprint)

'''

OPERATOR: --> GET /code
<-- :SERVICE 201 CREATED {'code':'somecode'}

Here the code is stored along with the user who requested it and service it came from. Service_Components stores the generated code
 as well.


User is redirected to service login with the code.
USER: --> GET /login?code=somecode

User logins and agrees the linking. Surrogate ID is generated and sent to OPERATOR.
SERVICE: --> POST /register?surrogate=SURROGRATEID1&code=somecode
<-- :OPERATOR 200 OK
Using the code we link surrogate id to MyData Account and service confirming the link.

'''
Service_ID = "SRV-SH14W4S3"
gen = {"generate": "EC", "cvr": "P-256", "kid": Service_ID}
token_key = jwk.JWK(**gen)
# templ = {Service_ID: loads(token_key.export_public())}
templ = {Service_ID: {"cr_keys": loads(token_key.export_public())}}


from functools import wraps
from flask import request, Response


def valid_credentials(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    compared_pw = users.get(username, None)
    if compared_pw is not None:
        return password == compared_pw
    else:
        return False

from instance import settings
def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login with your {} credentials"'.format(settings.NAME)})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not valid_credentials(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated



def timeme(method):
    def wrapper(*args, **kw):
        startTime = int(round(time.time() * 1000))
        result = method(*args, **kw)
        endTime = int(round(time.time() * 1000))

        debug_log.info("{}{}".format(endTime - startTime, 'ms'))
        return result

    return wrapper


class UserLogin(Resource):
    def __init__(self):
        super(UserLogin, self).__init__()
        self.helpers = Helpers(current_app.config)
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('code', type=str, help='session code')
        self.parser.add_argument('operator_id', type=str, help='Operator UUID.')
        self.parser.add_argument('return_url', type=str, help='Url safe Base64 coded return url.')
        self.parser.add_argument('Password', type=str, help="Password for user.")
        self.parser.add_argument('Email', type=str, help="Email/Username.")
        self.parser.add_argument('linkingFrom', type=str, help='Origin of the linking request(?)')  # TODO: Clarify?

    @error_handler
    @api_logging
    def get(self):
        args = self.parser.parse_args()
        # TODO: Use template file or get this from somewhere.
        if args["linkingFrom"] == "Operator":
            args["fromOperator"] = ""
        else:
            args["fromOperator"] = "hidden"
        tmpl_str = '''
        <html><header></header><body>
                    <form class="form-horizontal" action="" method="POST">
              <fieldset>
                <legend>Link {{provider}} with Operator({{ operator_id }})</legend>
                <div class="form-group">
                  <div class="col-lg-10 col-lg-offset-1">
                    Username:<input name="Email" id="username"></input><br>
                    Password:<input name="Password" id="pword"></input>
                    <button type="reset" class="btn btn-default">Cancel</button>
                    <button type="submit" class="btn btn-primary">Submit</button>
                  </div>
                </div>
              </fieldset>
              <div {{ fromOperator }}>
                <p> By linking service to Operator, you agree to the <a href="#LinkToToS">Terms of Service</a></p>
              </div>
              <input type="hidden" name="code" value="{{ code }}">
              <input type="hidden" name="return_url" value="{{ return_url }}">
              <input type="hidden" name="operator_id" value="{{ operator_id }}">
              <input type="hidden" name="linkingFrom" value="{{ linkingFrom }}">
            </form>
        </body></html>
        '''
        # Render Login template
        response = make_response(render_template_string(tmpl_str, **args), 200)
        response.headers["Content-Type"] = "text/html"
        return response

    # code = args["code"],
    # operator_id = args["operator_id"],
    # return_url = args["return_url"],
    # linkingFrom = args["linkingFrom"]
    @error_handler
    @api_logging
    def post(self):
        def link_surrogate_id(json_response, user_id, operator_id):
            response_user_id = self.helpers.get_user_id_with_code(args["code"])
            if response_user_id == user_id:
                pass
            else:
                raise DetailedHTTPException(
                    status=403,
                    detail={"msg": "Response was for different user_id than expected."
                             },
                    title="User ID mismatch."
                )
            debug_log.info("We got surrogate_id {} for user_id {}".format(json_response["surrogate_id"], user_id))
            debug_log.info(dumps(json_response, indent=2))
            self.helpers.storeSurrogateJSON(user_id, json_response["surrogate_id"], operator_id)
            return json_response["surrogate_id"]
        args = self.parser.parse_args()
        debug_log.info("Args contain:\n {}".format(dumps(args, indent=2)))
        debug_log.info(dumps(request.json, indent=2))
        user_id = args["Email"]
        user_pw = args["Password"]
        if not valid_credentials(user_id, user_pw):
            raise DetailedHTTPException(status=401,
                                        detail={"msg": "Unauthorized, check your login credentials."}
                                        )
        code = args["code"]
        self.helpers.store_code_user({code: user_id})

        debug_log.info("User logged in with id ({})".format(format(user_id)))

        endpoint = "/api/1.3/slr/surrogate_id"  # TODO: This needs to be fetched from somewhere.
        data = {"user_id": user_id, "operator_id": args["operator_id"]}
        result = post("{}{}".format(current_app.config["SERVICE_MGMNT_URL"], endpoint), json=data)
        if not result.ok:
            raise DetailedHTTPException(status=result.status_code,
                                        detail={
                                            "msg": "Something went wrong while posting to Service_Components Mgmnt to inform login was successful "
                                                   "and its alright to generate Surrogate_ID ",
                                            "Error from Service_Components Mgmnt": loads(result.text)},
                                        title=result.reason)
        debug_log.info(result.text)
        try:
            operator_id = args["operator_id"]
            surrogate_id = link_surrogate_id(loads(result.text), user_id, operator_id)  # Returns surrogate_id for convenience
            endpoint = "/api/1.3/slr/linking"  # TODO: This needs to be fetched from somewhere.

            data = {"code": code,
                    "operator_id": args["operator_id"],
                    "return_url": args["return_url"],
                    "surrogate_id": surrogate_id,
                    "user_id": user_id}
            linking_result = post("{}{}".format(current_app.config["SERVICE_MGMNT_URL"], endpoint), json=data)
            debug_log.debug("Service Linking resulted in:\n {}\n {}".format(linking_result.status_code,
                                                                            linking_result.text))

        except Exception as e:
            raise e
        reply_json = loads(linking_result.text)
        debug_log.info("Encoding json as reply to ui: \n{}".format(reply_json))
        if isinstance(reply_json, dict):
            reply_json = dumps(reply_json)
        return redirect("{}?results={}".format(decode64(args["return_url"]), encode64(reply_json)), code=302)

class StoreSlr(Resource):
    def __init__(self):
        super(StoreSlr, self).__init__()
        self.db_path = current_app.config["DATABASE_PATH"]
        self.helpers = Helpers(current_app.config)

    @timeme
    @error_handler
    @api_logging
    def post(self):
        def decode_payload(payload):
            #sq.task("Fix possible incorrect padding in payload")
            payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
            debug_log.info("After padding fix :{}".format(payload))

            #sq.task("Decode SLR payload and store it into object")
            debug_log.info(payload.encode())
            content = decode64(payload.encode())

            #sq.task("Load decoded payload as python dict")
            payload = loads(content.decode("utf-8"))
            debug_log.info("Decoded SLR payload:")
            debug_log.info(type(payload))
            debug_log.info(dumps(payload, indent=2))
            return payload
        store = request.json
        payload = decode_payload(store["data"]["slr"]["attributes"]["payload"])
        debug_log.info("Storing SLR into db")
        self.helpers.store_slr_JSON(json=request.json["data"]["slr"], slr_id=payload["link_id"], surrogate_id=payload["surrogate_id"])
        debug_log.info("Storing SSR into db")
        self.helpers.store_ssr_JSON(json=request.json["data"]["ssr"])
        return {"data": {"id": payload["link_id"], "type": "ServiceLinkRecord"}}, 201


class StoreSSR(Resource):
    def __init__(self):
        super(StoreSSR, self).__init__()
        config = current_app.config
        self.helpers = Helpers(config)

    @timeme
    @error_handler
    @api_logging
    def post(self):

        # TODO: This is as naive as it gets, needs some verifications regarding ssr,
        # or are we leaving this to firewalls, eg. Only this host(operator) can use this endpoint.
        try:
            self.helpers.store_ssr_JSON(json=request.json["data"])
            return {"id":request.json["data"]["id"]}, 201
        except Exception as e:
            debug_log.exception(e)
            raise e

api.add_resource(UserLogin, '/login')
api.add_resource(StoreSlr, '/store_slr')
api.add_resource(StoreSSR, '/store_ssr')
