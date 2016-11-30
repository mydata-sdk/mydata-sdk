# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import traceback
from json import loads, dumps
from uuid import uuid4 as guid
import time
from DetailedHTTPException import DetailedHTTPException, error_handler
from Templates import Sequences
from flask import request, Blueprint, current_app
from flask_cors import CORS
from flask_restful import Resource, Api
from helpers import AccountManagerHandler, Helpers, ServiceRegistryHandler
from requests import post

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
        self.operator_key = self.Helpers.get_key()
        self.request_timeout = self.app.config["TIMEOUT"]

        self.payload = \
            {
                "version": "1.2",
                "link_id": "",
                "operator_id": operator_id,
                "service_id": "",
                "surrogate_id": "",
                "operator_key": self.operator_key["pub"],
                "cr_keys": "",
                "iat": int(time.time()),
            }
        debug_log.info("SLR payload in init is: \n{}".format(dumps(self.payload, indent=2)))
        self.service_registry_handler = ServiceRegistryHandler(current_app.config["SERVICE_REGISTRY_SEARCH_DOMAIN"],
                                                               current_app.config["SERVICE_REGISTRY_SEARCH_ENDPOINT"])
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]

        try:
            self.AM = AccountManagerHandler(self.am_url, self.am_user, self.am_password, self.timeout)
        except Exception as e:
            debug_log.exception(e)
            debug_log.warn("Initialization of AccountManager failed. We will crash later but note it here.\n{}"
                           .format(repr(e)))

    @error_handler
    def post(self):
        try:
            debug_log.info("RegisterSurrogate method post got following parameters as json:\n{}"
                           .format(dumps(request.json, indent=2)))
            sq.task("Load json payload as object")
            js = request.json

            sq.task("Load account_id and service_id from database")
            stored_session_from_db = self.Helpers.query_db_multiple("select json from session_store where code=%s;",
                                                   (js["code"],),
                                                   one=True)[0]
            debug_log.debug("Type of session data fetched from db is: {}".format(type(stored_session_from_db)))
            debug_log.debug("The session data contains: {}".format(stored_session_from_db))
            session_data = loads(stored_session_from_db)
            debug_log.debug("{}  {}".format(type(stored_session_from_db), stored_session_from_db))
            account_id = session_data["account_id"]
            self.payload["service_id"] = session_data["service_id"]

            # Check Surrogate_ID exists.
            # Fill token_key
            try:
                sq.task("Verify surrogate_id and token_key exist in the payload json")
                token_key = js["token_key"]
                self.payload["surrogate_id"] = js["surrogate_id"]
                #self.payload["token_key"] = {"key": token_key}

                sq.task("Store surrogate_id and keys for CR steps later on.")
                service_keys = {"token_key": token_key,
                                "pop_key": token_key}  # TODO: Get pop_key here?

                self.Helpers.store_service_key_json(kid=token_key["kid"],
                                                    surrogate_id=js["surrogate_id"],
                                                    key_json=service_keys)
            except Exception as e:
                debug_log.exception(e)
                raise DetailedHTTPException(exception=e,
                                            detail={"msg": "Received Invalid JSON that may not contain surrogate_id",
                                                    "json": js})

            #sq.task("Fetch and fill token_issuer_keys")
            # TODO: Token keys separetely when the time is right.
            #self.payload["token_issuer_keys"][0] = self.Helpers.get_key()["pub"]

            # Create template
            self.payload["link_id"] = str(guid())
            # TODO: Currently you can generate endlessly new slr even if one exists already

            sq.task("Fill template for Account Manager")
            template = {"code": js["code"],
                        "data": {
                            "slr": {
                                "type": "ServiceLinkRecord",
                                "attributes": self.payload,
                            },
                                "surrogate_id": {
                                    "type": "SurrogateId",
                                    "attributes":{
                                        "surrogate_id": self.payload["surrogate_id"],
                                        "service_id": self.payload["service_id"],
                                        "account_id": account_id
                                    }
                                }
                            },
                         }

            debug_log.info("########### Template for Account Manager #")
            debug_log.info(dumps(template, indent=2))
            debug_log.info("########################################")

            sq.send_to("Account Manager", "Sign SLR at Account Manager")
            try:
                reply = self.AM.sign_slr(template, account_id)
            except AttributeError as e:
                raise DetailedHTTPException(status=502,
                                            title="It would seem initiating Account Manager Handler has failed.",
                                            detail="Account Manager might be down or unresponsive.",
                                            trace=traceback.format_exc(limit=100).splitlines())
            debug_log.info(dumps(reply, indent=2))

            # Parse JSON form Account Manager to format Service_Mgmnt understands.
            try:
                req = {"data":
                           {"code": js["code"],
                            },
                       "slr": reply["data"]["slr"]["attributes"]["slr"]
                       }

                debug_log.info("SLR in format sent to Service Mgmnt: {}".format(dumps(req, indent=2)))
            except Exception as e:
                raise DetailedHTTPException(exception=e,
                                            detail="Parsing JSON form Account Manager "
                                                   "to format Service_Mgmnt understands has failed.",
                                            trace=traceback.format_exc(limit=100).splitlines())

            try:
                sq.send_to("Service_Components Mgmnt", "Send created and signed SLR to Service_Components Mgmnt")
                endpoint = "/api/1.2/slr/slr"  # TODO Where do we get this endpoint?
                service_url = self.service_registry_handler.getService_url(self.payload["service_id"].encode())
                debug_log.info("Service_ulr = {}, type: {}".format(service_url, type(service_url)))
                response = post("{}{}".format(service_url, endpoint), json=req, timeout=self.request_timeout)
                debug_log.info("Service Mgmnt replied with status code ({})".format(response.status_code))
                if not response.ok:
                    raise DetailedHTTPException(status=response.status_code,
                                                detail={"Error from Service_Components Mgmnt": loads(response.text)},
                                                title=response.reason)
            except DetailedHTTPException as e:
                raise e
            except Exception as e:
                raise DetailedHTTPException(exception=e, detail="Sending SLR to service has failed",
                                            trace=traceback.format_exc(limit=100).splitlines())


        except DetailedHTTPException as e:
            raise e
        except Exception as e:
            raise DetailedHTTPException(title="Creation of SLR has failed.", exception=e,
                                        trace=traceback.format_exc(limit=100).splitlines())

api.add_resource(RegisterSurrogate, '/link')
