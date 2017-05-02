# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import traceback
from json import loads

from flask import Blueprint, current_app, render_template_string, make_response, redirect
from flask_cors import CORS
from flask_restful import Resource, Api
from requests import get, post
from requests.exceptions import ConnectionError, Timeout
from base64 import urlsafe_b64encode
from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_op import Helpers, ServiceRegistryHandler, Sequences
from uuid import uuid4 as guid
import time
'''

Operator_Components Mgmnt->Service_Components Mgmnt: Fetch code from service_mgmnt
Service_Components Mgmnt->Service_Components Mgmnt: Generate code
Service_Components Mgmnt->Service_Components Mgmnt: Store code in db
Service_Components Mgmnt-->Operator_Components Mgmnt: Returning code
Operator_Components Mgmnt->Operator_Components Mgmnt: Check code request is valid
Operator_Components Mgmnt->Operator_Components Mgmnt: Load code object for use
Operator_Components Mgmnt->Operator_Components Mgmnt: Add user_id to code dictionary {'code': 'code', 'user_id': 'user_id'}
Operator_Components Mgmnt->Service_Components Mgmnt: Redirect user to Service_Components Mgmnt login

'''

# Blueprint and Flask api stuff
api_SLR_Start = Blueprint("api_SLR_Start", __name__)
CORS(api_SLR_Start)
api = Api()
api.init_app(api_SLR_Start)

# Logger stuff
debug_log = logging.getLogger("debug")
sq = Sequences("Operator_Components Mgmnt")

class StartSlrFlow(Resource):
    def __init__(self):
        """

        """
        super(StartSlrFlow, self).__init__()
        self.service_registry_handler = ServiceRegistryHandler(current_app.config["SERVICE_REGISTRY_SEARCH_DOMAIN"],
                                                               current_app.config["SERVICE_REGISTRY_SEARCH_ENDPOINT"])
        self.request_timeout = current_app.config["TIMEOUT"]
        self.uid = current_app.config["UID"]
        self.helper = Helpers(current_app.config)
        self.store_session = self.helper.store_session

    @error_handler
    def get(self, account_id, service_id):
        """

        :param account_id: Account Manager user id
        :param service_id: Service id as in Service Registry
        """
        debug_log.info("#### Request to start SLR flow with parameters: account_id ({}), service_id ({})"
                       .format(account_id, service_id))
        try:

            # We need to store some session information for later parts of flow.
            session_information = {}

            sq.task("Fetch service address from Service Registry")
            service_json = self.service_registry_handler.getService(service_id)
            service_domain = service_json["serviceInstance"][0]["loginDomain"] # Domain to Login of Service
            service_access_uri = service_json["serviceInstance"][0]["serviceAccessEndPoint"]["serviceAccessURI"]
            service_login_uri = service_json["serviceInstance"][0]["loginUri"]

            sq.task("Generate code for session")
            code = str(guid())
            session_time = time.time()  # TODO: Use this. Make changes to DataBase to store it.

            debug_log.info("Session information contains: code {}, account id {} and service_id {}"
                           .format(code, account_id, service_id))

            sq.task("Store session_information to database")
            session_information[code] = {"account_id": account_id, "service_id": service_id}
            self.store_session(session_information)

            service_endpoint = "{}{}{}".format(service_domain, service_access_uri, service_login_uri)
            service_query = "?code={}&operator_id={}&return_url={}&linkingFrom={}".format(
                # TODO: Get return url from somewhere
                code, self.uid, urlsafe_b64encode("http://localhost:5000/"), "Operator")

            debug_log.info("Redirect url with parameters:\n{}{}\nCode contains: {}".format(service_endpoint,
                                                                                           service_query,
                                                                                           code))
            sq.send_to("UI(Operator)", "Redirect user to Service Mockup login")
            response = make_response(redirect(service_endpoint+service_query))
            return response

        except DetailedHTTPException as e:
            raise DetailedHTTPException(exception=e,
                                        title="SLR registration failed.",
                                        status=500,
                                        detail="Something failed during creation of SLR.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        except Exception as e:
            raise DetailedHTTPException(status=500,
                                        title="Something went really wrong during SLR registration.",
                                        detail="Error: {}".format(repr(e)),
                                        exception=e,
                                        trace=traceback.format_exc(limit=100).splitlines())

api.add_resource(StartSlrFlow, '/account/<string:account_id>/service/<string:service_id>')
