# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import traceback
from json import loads

from flask import Blueprint, current_app
from flask_cors import CORS
from flask_restful import Resource, Api
from requests import get, post
from requests.exceptions import ConnectionError, Timeout

from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_op import Helpers, ServiceRegistryHandler, Sequences

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
            try:
                # We need to store some session information for later parts of flow.
                session_information = {}

                sq.task("Fetch service address from Service Registry")
                service_json = self.service_registry_handler.getService(service_id)
                service_domain = service_json["serviceInstance"][0]["domain"]
                service_access_uri = service_json["serviceInstance"][0]["serviceAccessEndPoint"]["serviceAccessURI"]
                service_login_uri = service_json["serviceInstance"][0]["loginUri"]

                # Endpoint address for getting code should be fetched somewhere as well.
                # This is now expecting that every service will use the same endpoint which is unlikely.
                service_endpoint = "/slr/code"  # TODO: Comment above
                service_endpoint = "{}{}{}".format(service_domain, service_access_uri, service_endpoint)

                sq.send_to("Service_Components Mgmnt", "Fetch code from service_mgmnt")
                result = get(service_endpoint, timeout=self.request_timeout)
                code_status = result.status_code

                sq.task("Check code request is valid")
                debug_log.info("Status for the code request is: {}".format(code_status))
                if code_status is 200:
                    sq.task("Load code object for use")
                    code = loads(result.text)
                    debug_log.info("Session information contains: code {}, account id {} and service_id {}"
                                   .format(result.text, account_id, service_id))

                    sq.task("Store session_information to database")
                    session_information[code["code"]] = {"account_id": account_id, "service_id": service_id}
                    self.store_session(session_information)

                else:
                    raise DetailedHTTPException(status=code_status,
                                                detail={"msg": "Fetching code from Service_Components Mgmnt failed.",
                                                        "Errors From Service Mgmnt": loads(result.text)},
                                                title=result.reason)
            except Timeout:
                raise DetailedHTTPException(status=504,
                                            title="Request to Service_Components Mgmnt failed due to TimeoutError.",
                                            detail="Service_Components Mgmnt might be under heavy load,"
                                                   " request for code got timeout.",
                                            trace=traceback.format_exc(limit=100).splitlines())
            except ConnectionError:
                raise DetailedHTTPException(status=503,
                                            title="Request to Service_Components Mgmnt failed due to ConnectionError.",
                                            detail="Service_Components Mgmnt might be down or unresponsive.",
                                            trace=traceback.format_exc(limit=100).splitlines())

            sq.task("Add user_id(Account) to response from Service dictionary")
            code["user_id"] = account_id

            try:
                service_endpoint = "{}{}{}".format(service_domain, service_access_uri, service_login_uri)
                sq.send_to("Service_Components Mgmnt", "Redirect user to Service_Components Mgmnt login")
                result = post(service_endpoint, json=code, timeout=self.request_timeout)
                debug_log.info("#### Response to SLR flow end point: {}\n{}".format(result.status_code, result.text))
                if not result.ok:
                    raise DetailedHTTPException(status=result.status_code,
                                                detail={
                                                    "msg": "Something went wrong while Logging in with code"
                                                           " to Service_Components Mgmnt",
                                                    "Error from Service_Components Mgmnt": loads(result.text)},
                                                title=result.reason)

            except Timeout:
                raise DetailedHTTPException(status=504,
                                            title="Request to Service_Components Mgmnt failed due to TimeoutError.",
                                            detail="Service_Components Mgmnt might be under heavy load,"
                                                   " request for code got timeout.",
                                            trace=traceback.format_exc(limit=100).splitlines())
            except ConnectionError:
                raise DetailedHTTPException(status=504,
                                            title="Request to Service_Components Mgmnt failed due to ConnectionError.",
                                            detail="Service_Components Mgmnt might be down or unresponsive.",
                                            trace=traceback.format_exc(limit=100).splitlines())

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
