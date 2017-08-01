# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import time
import traceback
from json import loads, dumps
from uuid import uuid4 as guid

from flask import request, Blueprint, current_app
from flask_cors import CORS
from flask_restful import Resource, Api
from requests import post

from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_op import Helpers, ServiceRegistryHandler, Sequences, get_am, format_request

# Flask init
api_SLR_RegisterSur = Blueprint("api_SLR_RegisterSur", __name__)
CORS(api_SLR_RegisterSur)
api = Api()
api.init_app(api_SLR_RegisterSur)

# Logging
debug_log = logging.getLogger("debug")
sq = Sequences("Operator_Components Mgmnt")

'''
Service_Components Mgmnt->Operator_Components Mgmnt: Send Operator_Components request to make SLR
Operator_Components Mgmnt->Operator_Components Mgmnt: Load json payload as object
Operator_Components Mgmnt->Operator_Components Mgmnt: Load account_id and service_id from database
Operator_Components Mgmnt->Operator_Components Mgmnt: Verify surrogate_id and token_key exist
Operator_Components Mgmnt->Operator_Components Mgmnt: Fill template for Account Mgmnt
Operator_Components Mgmnt->Account Manager: Sign SLR at Account Manager
Operator_Components Mgmnt->Service_Components Mgmnt: Send created and signed SLR to Service_Components Mgnt

'''

class RegisterSurrogate(Resource):
    def __init__(self):
        super(RegisterSurrogate, self).__init__()
        self.app = current_app
        self.Helpers = Helpers(self.app.config)
        operator_id = self.app.config["UID"]
        self.service_registry_handler = ServiceRegistryHandler(current_app.config["SERVICE_REGISTRY_SEARCH_DOMAIN"],
                                                               current_app.config["SERVICE_REGISTRY_SEARCH_ENDPOINT"])
        self.operator_key = self.Helpers.get_key()
        self.request_timeout = self.app.config["TIMEOUT"]

        self.payload = \
            {
                "version": "1.3",
                "link_id": "",
                "operator_id": operator_id,
                "service_id": "",
                "surrogate_id": "",
                "operator_key": self.operator_key["pub"],
                "cr_keys": "",
                "iat": 0,  # Set below once we know link_id
            }
        debug_log.info("SLR payload in init is: \n{}".format(dumps(self.payload, indent=2)))
        self.service_registry_handler = ServiceRegistryHandler(current_app.config["SERVICE_REGISTRY_SEARCH_DOMAIN"],
                                                               current_app.config["SERVICE_REGISTRY_SEARCH_ENDPOINT"])
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]

    @error_handler
    def post(self):
        debug_log.info(format_request(request))
        try:

            debug_log.info("RegisterSurrogate method post got following parameters as json:\n{}"
                           .format(dumps(request.json, indent=2)))
            sq.task("Load json payload as object")
            js = request.json

            sq.task("Load account_id and service_id from database")
            code = js["code"]
            try:
                stored_session_from_db = self.Helpers.query_db_multiple("select json from session_store where code=%s;",
                                                                    (code,),
                                                                    one=True)[0]
            except TypeError as e:
                debug_log.info("Failed restoring session from DB with code '{}'".format(code))
                debug_log.exception(e)
                raise DetailedHTTPException(status=403,
                                            detail={"msg": "Invalid or expired session"},
                                            title="Invalid session")
            debug_log.debug("Type of session data fetched from db is: {}".format(type(stored_session_from_db)))
            debug_log.debug("The session data contains: {}".format(stored_session_from_db))
            session_data = loads(stored_session_from_db)
            debug_log.debug("{}  {}".format(type(stored_session_from_db), stored_session_from_db))
            account_id = session_data["account_id"]

            # Get Account Manager Handler
            AM = get_am(current_app, request.headers)
            key_check = AM.verify_user_key(account_id, user_key=session_data["user_key"])
            debug_log.info("Verifying User Key resulted: {}".format(key_check))

            self.payload["service_id"] = session_data["service_id"]
            service_info = self.service_registry_handler.getService(self.payload["service_id"])
            # TODO: Use serviceType field added into ServiceDescription
            service_type = service_info["serviceDescription"]["serviceDataDescription"][0]["dataset"][0]["serviceDataType"]

            # Check Surrogate_ID exists.
            # Fill token_key
            try:
                sq.task("Verify surrogate_id and token_key exist in the payload json")
                self.payload["surrogate_id"] = js["surrogate_id"]
                #self.payload["token_key"] = {"key": token_key}

                if service_type == "input" or service_type == "both":
                    sq.task("Store surrogate_id and keys for CR steps later on.")
                    token_key = js["token_key"]  # Todo: source has no need to send this, make the difference.
                    service_keys = {"token_key": token_key,
                                    "pop_key": token_key}

                    self.Helpers.store_service_key_json(kid=token_key["kid"],
                                                        surrogate_id=js["surrogate_id"],
                                                        key_json=service_keys,
                                                        service_id=service_info["id"])
            except Exception as e:
                debug_log.exception(e)
                self.Helpers.delete_session(code)
                raise DetailedHTTPException(exception=e,
                                            detail={"msg": "Received Invalid JSON that may not contain surrogate_id",
                                                    "json": js})

            # Create template
            # TODO: Currently you can generate endlessly new slr even if one exists already
            if service_type == "input" or service_type == "both":
                result = AM.init_slr(code, pop_key=token_key)
            else:
                result = AM.init_slr(code)

            self.payload["link_id"] = result
            self.payload["iat"] = int(time.time())


            sq.task("Fill template for Account Manager")

            template = {"code": code,
                        "data": {
                            "type": "ServiceLinkRecord",
                            "attributes": self.payload
                            }
                        }

            debug_log.info("########### Template for Account Manager #")
            debug_log.info(dumps(template, indent=2))
            debug_log.info("########################################")

            sq.send_to("Account Manager", "Sign SLR at Account Manager")
            try:
                reply = AM.sign_slr(template, account_id)
            except AttributeError as e:
                self.Helpers.delete_session(code)
                raise DetailedHTTPException(status=502,
                                            title="It would seem initiating Account Manager Handler has failed.",
                                            detail="Account Manager might be down or unresponsive.",
                                            trace=traceback.format_exc(limit=100).splitlines())
            debug_log.info(dumps(reply, indent=2))

            # Parse JSON form Account Manager to format Service_Mgmnt understands.
            try:
                req = {"data":
                           {"code": code,
                            },
                       "slr": reply["data"]["attributes"]
                       }

                debug_log.info("SLR in format sent to Service Mgmnt: {}".format(dumps(req, indent=2)))
            except Exception as e:
                raise DetailedHTTPException(exception=e,
                                            detail="Parsing JSON form Account Manager "
                                                   "to format Service_Mgmnt understands has failed.",
                                            trace=traceback.format_exc(limit=100).splitlines())

            try:
                sq.send_to("Service_Components Mgmnt", "Send created and signed SLR to Service_Components Mgmnt")
                endpoint = "/api/1.3/slr/slr"  # TODO Where do we get this endpoint?
                service_url = self.service_registry_handler.getService_url(self.payload["service_id"].encode())
                debug_log.info("Service_ulr = {}, type: {}".format(service_url, type(service_url)))
                response = post("{}{}".format(service_url, endpoint), json=req, timeout=self.request_timeout)
                debug_log.info("Service Mgmnt replied with status code ({})".format(response.status_code))
                if not response.ok:
                    self.Helpers.delete_session(code)
                    raise DetailedHTTPException(status=response.status_code,
                                                detail={"Error from Service_Components Mgmnt": loads(response.text)},
                                                title=response.reason)
            except DetailedHTTPException as e:
                raise e
            except Exception as e:
                self.Helpers.delete_session(code)
                raise DetailedHTTPException(exception=e, detail="Sending SLR to service has failed",
                                            trace=traceback.format_exc(limit=100).splitlines())

        except DetailedHTTPException as e:
            self.Helpers.delete_session(code)
            raise e
        except Exception as e:
            self.Helpers.delete_session(code)
            raise DetailedHTTPException(title="Creation of SLR has failed.", exception=e,
                                        trace=traceback.format_exc(limit=100).splitlines())
        # SLR is made at this point and returned to the Service Mgmnt, session can be deleted.
        self.Helpers.delete_session(code)
        return loads(response.text), 201

api.add_resource(RegisterSurrogate, '/link')
