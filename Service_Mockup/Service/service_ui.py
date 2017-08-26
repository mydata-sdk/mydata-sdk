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

api_service_ui_blueprint = Blueprint("api_service_ui_blueprint", __name__)

CORS(api_service_ui_blueprint)
api = Api()
api.init_app(api_service_ui_blueprint)


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
        if not auth or not check_auth(auth.username, auth.password):
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


class LinkingUi(Resource):
    def __init__(self):
        super(LinkingUi, self).__init__()
        self.helpers = Helpers(current_app.config)
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('operator_id', type=str, help='Operator UUID.')
        self.parser.add_argument('Password', type=str, help="Password for user.")
        self.parser.add_argument('Email', type=str, help="Email/Username.")


    @error_handler
    @api_logging
    def get(self):
        args = self.parser.parse_args()
        # TODO: Use template file or get this from somewhere.
        args["provider"] = settings.NAME
        tmpl_str = '''
        <html>
            <header>
                <!-- Latest compiled and minified CSS -->
                <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
                
                <!-- Optional theme -->
                <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
                
                <!-- Latest compiled and minified JavaScript -->
                <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
            </header>
            <body>
                <div class="container">
                 <div class="row">
                  <div class="col-md-12">
                      <div class="col-md-4"><br/>
                      </div>
                      <div class="col-md-4">
                        <form class="form-horizontal" action="" method="POST">
                          <fieldset>
                            <legend>Link {{provider}} with Operator({{ operator_id }})</legend>
                            <div class="form-group">
                              <div class="col-lg-10 col-lg-offset-1">
                                Username:<input name="Email" id="username"></input><br>
                                Password :<input name="Password" id="pword"></input>
                                <div align=center>
                                    <button type="reset" class="btn btn-danger">Cancel</button>
                                    <button type="submit" class="btn btn-success">Submit</button>
                                </div>
                              </div>
                            </div>
                          </fieldset>
                          <div {{ fromOperator }}>
                            <p> By linking service to Operator, you agree to the <a href="#LinkToToS">Terms of Service</a></p>
                            <hr><p> You will be redirected to your MyData Account for login.
                          </div>
                          <input type="hidden" name="operator_id" value="{{ operator_id }}">
            
                        </form>
                      </div>
                  </div>
                 </div>
                </div>
            </body>
        </html>
        '''
        # Render Login template
        response = make_response(render_template_string(tmpl_str, **args), 200)
        response.headers["Content-Type"] = "text/html"
        return response

    @error_handler
    @api_logging
    def post(self):
        args = self.parser.parse_args()
        operator_id = args["operator_id"]
        user_id = args["Email"]
        user_pw = args["Password"]

        if not valid_credentials(user_id, user_pw):
            raise DetailedHTTPException(status=401,
                                        detail={"msg": "Unauthorized, check your login credentials."}
                                        )


        # Send Management the Operator id and get Surrogate_ID
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
        surrogate_id = loads(result.text)["surrogate_id"]

        # Link surrogate_id to the user
        def link_surrogate_id(surrogate_id, user_id, operator_id):
            debug_log.info("We got surrogate_id {} for user_id {} on operator {}".format(surrogate_id, user_id, operator_id))
            self.helpers.storeSurrogateJSON(user_id, surrogate_id, operator_id)
        link_surrogate_id(surrogate_id, user_id, operator_id)

        # Redirect user to Operator UI
        service_id = settings.SERVICE_ID
        return_url = "http://"+request.headers["HOST"]+"/" #TODO: less hardcoded stuff
        operator_login_url = self.helpers.get_operator_login_url(operator_id)

        operator_endpoint = "{}".format(operator_login_url)
        operator_query = "?surrogate_id={}&service_id={}&return_url={}&linkingFrom={}".format(
            # TODO: Get return url from somewhere
            surrogate_id, service_id, encode64(return_url), "Service")

        debug_log.info("Redirect url with parameters:\n{}{}\nSurrogate_id is: {}".format(operator_endpoint,
                                                                                       operator_query,
                                                                                       surrogate_id))
        response = make_response(redirect(operator_endpoint + operator_query))
        return response

api.add_resource(LinkingUi, '/linking_service')
