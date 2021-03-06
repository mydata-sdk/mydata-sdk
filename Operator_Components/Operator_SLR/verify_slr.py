# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import traceback
from base64 import urlsafe_b64decode as decode
from json import loads, dumps

from flask import request, Blueprint, current_app
from flask_cors import CORS
from flask_restful import Resource, Api

from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_op import AccountManagerHandler, Helpers, Sequences, get_am, api_logging

# Flask init
api_SLR_Verify = Blueprint("api_SLR_Verify", __name__)
CORS(api_SLR_Verify)
api = Api()
api.init_app(api_SLR_Verify)

# Logging
debug_log = logging.getLogger("debug")
sq = Sequences("OpMgmt")

'''
Service_Components Mgmnt->Operator_Components Mgmnt: Verify SLR(JWS)
Operator_Components Mgmnt->Operator_Components Mgmnt: Load SLR to object
Operator_Components Mgmnt->Operator_Components Mgmnt: Fix possible incorrect padding in payload
Operator_Components Mgmnt->Operator_Components Mgmnt: Load slr payload as object
Operator_Components Mgmnt->Operator_Components Mgmnt: Decode payload and store it into object
Operator_Components Mgmnt->Operator_Components Mgmnt: Fetch link_id from decoded payload
Operator_Components Mgmnt->Operator_Components Mgmnt: Load account_id from database
Operator_Components Mgmnt->Operator_Components Mgmnt: Load decoded payload as python dict
Operator_Components Mgmnt->Operator_Components Mgmnt: Load slr and code from json payload
Operator_Components Mgmnt->Account Manager: Verify SLR at Account Manager.
Operator_Components Mgmnt-->Service_Components Mgmnt: 201, SLR VERIFIED
'''

class VerifySLR(Resource):
    def __init__(self):
        super(VerifySLR, self).__init__()
        self.app = current_app
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]
        self.Helpers = Helpers(current_app.config)

    @error_handler
    @api_logging
    def post(self):
        sq.task("Load SLR to object")
        slr = request.json["slr"]
        debug_log.info("{} {}".format("SLR from request payload json:\n", slr))

        sq.task("Load slr payload as object")
        slr_payload = slr["payload"]
        debug_log.info("{} {}".format("Payload before fix:", slr_payload))

        sq.task("Fix possible incorrect padding in payload")
        slr_payload += '=' * (-len(slr_payload) % 4)  # Fix incorrect padding of base64 string.
        debug_log.info("{} {}".format("Payload after fix :", slr_payload))

        sq.task("Decode slr payload to a string and store it into variable")
        content = decode(slr_payload.encode())

        sq.task("Load slr payload string as python dict")
        slr_payload = loads(content.decode("utf-8"))
        debug_log.info(slr_payload)
        debug_log.info(type(slr_payload))

        sq.task("Fetch code from request")
        code = request.json["data"]["code"]
        debug_log.info("Found code {} from request".format(code))

        try:
            ##
            # Verify SLR with key from Service_Components Management
            ##
            sq.task("Load account_id from database")
            query = self.Helpers.query_db("select * from session_store where code=%s;", (code,))
            session_data = loads(query)
            account_id = session_data["account_id"]

            AM = get_am(current_app, request.headers)
            key_check = AM.verify_user_key(account_id, user_key=session_data["user_key"])
            debug_log.info("Verifying User Key resulted: {}".format(key_check))

            debug_log.info("################Verify########################")
            debug_log.info(dumps(request.json))
            debug_log.info("########################################")

            sq.send_to("Account Manager", "Verify SLR at Account Manager.")
            try:
                reply = AM.verify_slr(slr_payload, code, slr, account_id)
            except AttributeError as e:
                raise DetailedHTTPException(status=500,
                                            title="Verification of SLR failed",
                                            detail="SLR verification has failed.",
                                            trace=traceback.format_exc(limit=100).splitlines())
            if reply.ok:
                # TODO: Should session db be cleared here?
                sq.reply_to("Service_Components Mgmnt", "201, SLR VERIFIED")
                debug_log.info("Account Manager replied {} with content:\n{}".format(reply.status_code, reply.text))
                return reply.text, reply.status_code
            else:
                raise DetailedHTTPException(status=reply.status_code,
                                            detail={
                                                "msg": "Something went wrong while verifying SLR at Account Manager",
                                                "content": reply.json()},
                                            title=reply.reason
                                            )
        except DetailedHTTPException as e:
            raise e

        except Exception as e:
            raise DetailedHTTPException(exception=e,
                                        detail="Verifying SLR failed for unknown reason, access is denied.")


api.add_resource(VerifySLR, '/verify')
