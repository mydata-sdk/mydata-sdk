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
from helpers_mock import Helpers

debug_log = logging.getLogger("debug")

api_Root_blueprint = Blueprint("api_Root_blueprint", __name__)  # TODO Rename better

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


# post("http://localhost:6666/key", json=templ)
# op_key = loads(get("http://localhost:6666/key/"+"OPR-ID-RANDOM").text)
# Operator_pub = jwk.JWK(**op_key)


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
    def get(self):
        args = self.parser.parse_args()
        debug_log.info("Mockup UserLogin GET got args: \n{}".format(dumps(args, indent=2)))
        # TODO: Use template file or get this from somewhere.
        if args["linkingFrom"] == "Operator":
            args["fromOperator"] = ""
        else:
            args["fromOperator"] = "hidden"
        tmpl_str = '''
        <html><header></header><body>
                    <form class="form-horizontal" action="" method="POST">
              <fieldset>
                <legend>Login to {{provider}}</legend>
                <div class="form-group">
                  <label for="inputEmail" class="col-lg-1 control-label">Email</label>
                  <div class="col-lg-10">
                    <input class="form-control" id="inputEmail" placeholder="Email" name="Email" type="text">
                  </div>
                </div>
                <div class="form-group">
                  <label for="inputPassword" class="col-lg-1 control-label">Password</label>
                  <div class="col-lg-10">
                    <input class="form-control" id="inputPassword" placeholder="Password" name="Password" type="password">
                  </div>
                </div>
                <div class="form-group">
                  <div class="col-lg-10 col-lg-offset-1">
                    <button type="reset" class="btn btn-default">Cancel</button>
                    <button type="submit" class="btn btn-primary">Submit</button>
                  </div>
                </div>
              </fieldset>
              <div {{ fromOperator }}>
                <p> By signing in you agree to the <a href="#LinkToToS">Terms of Service</a></p>
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
        return response

    # code = args["code"],
    # operator_id = args["operator_id"],
    # return_url = args["return_url"],
    # linkingFrom = args["linkingFrom"]
    @timeme
    @error_handler
    def post(self):
        def auth_user(username, password):
            if (username is not None and len(username) > 0) and (password is not None and len(password) > 0):

                return True
            else:
                return False

        def link_surrogate_id(json_response, user_id):
            try:  # Remove this check once debugging is done. TODO
                response_user_id = self.helpers.get_user_id_with_code(request.json["code"])
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
                self.helpers.storeSurrogateJSON({user_id: json_response})
                return json_response["surrogate_id"]
            except Exception as e:
                debug_log.exception(e)
                pass

        args = self.parser.parse_args()
        debug_log.info("Mockup UserLogin POST args contain:\n {}".format(dumps(args, indent=2)))
        login_was_successfull = auth_user(args["Email"], args["Password"])
        debug_log.info("Login in with given credentials resulted in: {}".format(login_was_successfull))
        debug_log.info(dumps(request.json, indent=2))
        user_id = encode64(args["Email"])  # TODO: Placeholder for actual login.
        code = args["code"]
        self.helpers.store_code_user({code: user_id})

        debug_log.info("User logged in with id ({})".format(format(user_id)))

        endpoint = "/api/1.2/slr/auth"  # TODO: This needs to be fetched from somewhere.
        data = {"code": code, "user_id": user_id, "operator_id": args["operator_id"]}
        result = post("{}{}".format(current_app.config["SERVICE_MGMNT_URL"], endpoint), json=data)
        if not result.ok:
            raise DetailedHTTPException(status=result.status_code,
                                        detail={
                                            "msg": "Something went wrong while posting to Service_Components Mgmnt to inform login was successful "
                                                   "and its alright to generate Surrogate_ID ",
                                            "Error from Service_Components Mgmnt": loads(result.text)},
                                        title=result.reason)
        debug_log.info(result.text)
        surrogate_id = link_surrogate_id(loads(result.text), user_id)  # Returns surrogate_id for convenience
        endpoint = "/api/1.2/slr/linking"  # TODO: This needs to be fetched from somewhere.

        data = {"code": code,
                "operator_id": args["operator_id"],
                "return_url": args["return_url"],
                "surrogate_id": surrogate_id}
        linking_result = post("{}{}".format(current_app.config["SERVICE_MGMNT_URL"], endpoint), json=data)
        debug_log.debug("Service Linking resulted in:\n {}\n {}".format(linking_result.status_code,
                                                                        linking_result.text))

        return redirect("{}".format(decode64(args["return_url"])), code=302)


class RegisterSur(Resource):
    def __init__(self):
        super(RegisterSur, self).__init__()
#        self.db_path = current_app.config["DATABASE_PATH"]
        self.helpers = Helpers(current_app.config)

    @timeme
    @error_handler
    def post(self):
        try:  # Remove this check once debugging is done. TODO
            user_id = self.helpers.get_user_id_with_code(request.json["code"])
            debug_log.info("We got surrogate_id {} for user_id {}".format(request.json["surrogate_id"], user_id))
            debug_log.info(dumps(request.json, indent=2))
            self.helpers.storeSurrogateJSON({user_id: request.json})
        except Exception as e:
            pass


class StoreSlr(Resource):
    def __init__(self):
        super(StoreSlr, self).__init__()
        self.db_path = current_app.config["DATABASE_PATH"]
        self.helpers = Helpers(current_app.config)

    @timeme
    @error_handler
    def post(self):
        debug_log.info(dumps(request.json, indent=2))
        store = request.json
        self.helpers.storeJSON({store["data"]["surrogate_id"]: store})


api.add_resource(UserLogin, '/login')
api.add_resource(RegisterSur, '/link')
api.add_resource(StoreSlr, '/store_slr')
