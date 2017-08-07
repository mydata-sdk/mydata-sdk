# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import time
from json import loads, dumps

from flask import request, Blueprint, current_app, render_template_string, make_response, redirect
from flask_cors import CORS
from flask_restful import Resource, Api, reqparse
from jwcrypto import jwk
from requests import post, get

from base64 import urlsafe_b64encode as encode64
from base64 import urlsafe_b64decode as decode64

from uuid import uuid4 as guid
from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_op import Helpers, format_request, ServiceRegistryHandler


debug_log = logging.getLogger("debug")

api_operator_ui_blueprint = Blueprint("api_service_ui_blueprint", __name__)

CORS(api_operator_ui_blueprint)
api = Api()
api.init_app(api_operator_ui_blueprint)

from functools import wraps
from flask import request, Response



class LinkingUi(Resource):
    def __init__(self):
        super(LinkingUi, self).__init__()
        self.helper = Helpers(current_app.config)
        self.account_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.operator_id = current_app.config["OPERATOR_UID"]
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('surrogate_id', type=str, help='Surrogate_id from a service.')
        self.parser.add_argument('service_id', type=str, help='ID of linking service.')
        self.parser.add_argument('username', type=str, help='Username for MyDataAccount')
        self.parser.add_argument('pword', type=str, help='Password for MyDataAccount')
        self.parser.add_argument('return_url', type=str, help='Url safe Base64 coded return url.')
        self.parser.add_argument('linkingFrom', type=str, help='Origin of the linking request(?)')
        self.store_session = self.helper.store_session
        self.service_registry_handler = ServiceRegistryHandler(current_app.config["SERVICE_REGISTRY_SEARCH_DOMAIN"],
                                                               current_app.config["SERVICE_REGISTRY_SEARCH_ENDPOINT"])

    @error_handler
    def get(self):
        debug_log.info(format_request(request))
        args = self.parser.parse_args()
        args["operator_id"] = self.operator_id
        args["provider"] = args["service_id"]

        # Check headers for Account API key

        # If key is n


        # TODO: Use template file or get this from somewhere.
        tmpl_str = '''
        <html><header></header><body>
                    <form class="form-horizontal" action="" method="POST">
              <fieldset>
                <legend>Link {{provider}} with Operator({{ operator_id }})</legend>
                <div class="form-group">
                  <div class="col-lg-10 col-lg-offset-1">
                    Username:<input name="username" id="username"></input><br>
                    Password:<input name="pword" id="pword"></input>
                    <button type="reset" class="btn btn-default">Cancel</button>
                    <button type="submit" class="btn btn-primary">Submit</button>
                  </div>
                </div>
              </fieldset>
              <div {{ fromOperator }}>
                <p> By linking service to Operator, you agree to the <a href="#LinkToToS">Terms of Service</a></p>
              </div>
              <input type="hidden" name="surrogate_id" value="{{ surrogate_id }}">
              <input type="hidden" name="service_id" value="{{ service_id }}">
              <input type="hidden" name="return_url" value="{{ return_url }}">
              <input type="hidden" name="linkingFrom" value="{{ linkingFrom }}">
            </form>
        </body></html>
        '''
        # Render Login template
        response = make_response(render_template_string(tmpl_str, **args), 200)
        return response

    def post(self):
        debug_log.info(format_request(request))
        args = self.parser.parse_args()
        debug_log.info(dumps(args, indent=2))



        def get_api_key(account_url=self.account_url+"account/api/v1.3/", user=None, password=None, endpoint="external/auth/user/"):
            debug_log.info("\nFetching Account Key for account '{}' from endpoint: {}".format(user+":"+password, account_url+endpoint))
            api_json = get(account_url + endpoint, auth=(user, password))
            #debug_log.info("Received following key:\n {}".format(api_json))
            if api_json.ok:
                return loads(api_json.text)
            else:
                raise DetailedHTTPException(title="Authentication to Account failed.", status=403)


        # Check Account is valid account, this is dummy UI, this is dumm test.
        account_info = get_api_key(user=args["username"], password=args["pword"])
        account_id = account_info["account_id"]
        account_api_key = account_info["Api-Key-User"]

        # Initialize all common variables
        surrogate_id = args["surrogate_id"]
        service_id = args["service_id"]
        return_url = args["return_url"]


        # Generate Code for session
        code = str(guid())

        debug_log.info("Session information contains: code {}, account id {} and service_id {}".format(code,
                                                                                                       account_id,
                                                                                                       service_id))

        debug_log.info("Store session_information to database")

        session_information = {code: {"account_id": account_id,
                                      "service_id": service_id,
                                      "user_key": account_api_key}
                               }
        self.store_session(session_information)



        try:
            # Make request to register surrogate_id
            data = {"code": code,
                "operator_id": self.operator_id,
                "return_url": return_url,
                "surrogate_id": surrogate_id,
                }

            # Fetch service information:
            service_json = self.service_registry_handler.getService(service_id)
            service_domain = service_json["serviceInstance"][0]["domain"]  # Domain to Login of Service
            service_access_uri = service_json["serviceInstance"][0]["serviceAccessEndPoint"]["serviceAccessURI"]
            service_linking_uri = "/slr/linking"

            service_url = service_domain+service_access_uri+service_linking_uri

            # Initiate Service Link Process
            debug_log.info("Sending linking request to Service at: {}".format(service_url))
            linking_result = post(service_url, json=data)
            debug_log.debug("Service Linking resulted in:\n {}\n {}".format(linking_result.status_code,
                                                                            linking_result.text))
            # If SLR was created success fully load it as a dictionary, on errors we delete session.
            if linking_result.ok:
                reply_json = loads(linking_result.text)
            else:
                self.helper.delete_session(code)
                raise DetailedHTTPException(title=linking_result.reason,
                                            status=linking_result.status_code,
                                            detail={"msg": linking_result.text})
            debug_log.info("Encoding json as reply to ui: \n{}".format(reply_json))
            if isinstance(reply_json, dict):
                reply_json = dumps(reply_json)
            self.helper.delete_session(code)
            return redirect("{}?results={}".format(decode64(args["return_url"]), encode64(reply_json)), code=302)

        except DetailedHTTPException as e:
            self.helper.delete_session(code)
            raise e
        except Exception as e:
            self.helper.delete_session(code)
            raise DetailedHTTPException(status=500,
                                        exception=e,
                                        title="Something went wrong during service linking, try again.")


api.add_resource(LinkingUi, '/linking_service')