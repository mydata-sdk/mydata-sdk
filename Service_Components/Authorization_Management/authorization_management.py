# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import time
from json import dumps

from flask import request, Blueprint, current_app
from flask_cors import CORS
from flask_restful import Resource, Api

from DetailedHTTPException import DetailedHTTPException, error_handler
from Templates import sink_cr_schema, source_cr_schema, csr_schema
from helpers_srv import validate_json, SLR_tool, CR_tool, Helpers, Sequences, base_token_tool
from srv_tasks import get_AuthToken

api_Authorization_Mgmnt = Blueprint("api_Authorization_Mgmnt", __name__)

CORS(api_Authorization_Mgmnt)
api = Api()
api.init_app(api_Authorization_Mgmnt)

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

logger = logging.getLogger("sequence")
debug_log = logging.getLogger("debug")

sq = Sequences("Service_Components Mgmnt")


def timeme(method):
    def wrapper(*args, **kw):
        startTime = int(round(time.time() * 1000))
        result = method(*args, **kw)
        endTime = int(round(time.time() * 1000))

        debug_log("{}{}".format(endTime - startTime, 'ms'))
        return result

    return wrapper


class Install_CR(Resource):
    def __init__(self):
        super(Install_CR, self).__init__()
        self.helpers = Helpers(current_app.config)
        self.is_sink = current_app.config["IS_SINK"]
        self.is_source = current_app.config["IS_SOURCE"]
        self.operator_url = current_app.config["OPERATOR_URL"]
        self.db_path = current_app.config["DATABASE_PATH"]
    @error_handler
    def post(self):
        debug_log.info("arrived at Install_CR")
        cr_stuff = request.json

        debug_log.info(dumps(cr_stuff, indent=2))
        sq.task("Install CR/CSR")
        '''post

        :return: Returns 202
        '''

        sq.task("CR Received")
        crt = CR_tool()
        crt.cr = cr_stuff
        role = crt.get_role()
        sq.task("Verify CR format and mandatory fields")
        if role == "Source" and self.is_source:
            debug_log.info("Source CR")
            debug_log.info(dumps(crt.get_CR_payload(), indent=2))
            debug_log.info(type(crt.get_CR_payload()))
            errors = validate_json(source_cr_schema, crt.get_CR_payload())
            for e in errors:
                raise DetailedHTTPException(detail={"msg": "Validating Source CR format and fields failed",
                                                    "validation_errors": errors},
                                            title="Failure in CR validation",
                                            status=400)
        if role == "Sink" and self.is_sink:
            debug_log.info("Sink CR")
            errors = validate_json(sink_cr_schema, crt.get_CR_payload())
            for e in errors:
                raise DetailedHTTPException(detail={"msg": "Validating Sink CR format and fields failed",
                                                    "validation_errors": errors},
                                            title="Failure in CR validation",
                                            status=400)

        if ((role == "Source" and self.is_source) or (role == "Sink" and self.is_sink)) is False:
            raise DetailedHTTPException(detail={"msg": "Validating CR format and fields failed."
                                                       " It is possible CR didn't specify role or that Service is "
                                                       "configured to be nether sink, source or both"},
                                        title="Failure in CR validation",
                                        status=400)

        debug_log.info(dumps(crt.get_CR_payload(), indent=2))
        debug_log.info(dumps(crt.get_CSR_payload(), indent=2))

        sq.task("Verify CR integrity")
        # SLR includes CR keys which means we need to get key from stored SLR and use it to verify this
        # 1) Fetch surrogate_id so we can query our database for slr
        surr_id = crt.get_surrogate_id()
        slr_id = crt.get_slr_id()

        # Verify SLR is Active:
        if self.helpers.verify_slr_is_active(slr_id) is False:
            raise DetailedHTTPException(detail={"msg": "SLR not Active",},
                                        title="Consent Can't be granted with inactive SLR",
                                        status=403)

        debug_log.info("Fetched surr_id({}) and slr_id({})".format(surr_id, slr_id))

        slrt = SLR_tool()
        slrt.slr = self.helpers.get_slr(surr_id)
        verify_is_success = crt.verify_cr(slrt.get_cr_keys())
        if verify_is_success:
            sq.task("Verify CR is issued by authorized party")
            debug_log.info("CR was verified with key from SLR")
        else:
            raise DetailedHTTPException(detail={"msg": "Verifying CR failed",},
                                        title="Failure in CR verifying",
                                        status=403)

        sq.task("Verify CSR integrity")
        # SLR includes CR keys which means we need to get key from stored SLR and use it to verify this
        verify_is_success = crt.verify_csr(slrt.get_cr_keys())

        if verify_is_success:
            debug_log.info("CSR was verified with key from SLR")
        else:
            raise DetailedHTTPException(detail={"msg": "Verifying CSR failed",},
                                        title="Failure in CSR verifying",
                                        status=403)

        sq.task("Verify Status Record")

        sq.task("Verify CSR format and mandatory fields")
        errors = validate_json(csr_schema, crt.get_CSR_payload())
        for e in errors:
            raise DetailedHTTPException(detail={"msg": "Validating CSR format and fields failed",
                                                "validation_errors": errors},
                                        title="Failure in CSR validation",
                                        status=400)
        # 1) CSR has link to CR
        csr_has_correct_cr_id = crt.cr_id_matches_in_csr_and_cr()
        if csr_has_correct_cr_id:
            debug_log.info("Verified CSR links to CR")
        else:
            raise DetailedHTTPException(detail={"msg": "Verifying CSR cr_id == CR cr_id failed",},
                                        title="Failure in CSR verifying",
                                        status=403)

        # # Verify CR before we do intense DB lookups
        # verify_is_success = crt.verify_cr(slrt.get_cr_keys())
        # if verify_is_success:
        #     sq.task("Verify CR is issued by authorized party")
        #     debug_log.info("CR was verified with key from SLR")
        # else:
        #     raise DetailedHTTPException(detail={"msg": "Verifying CR failed",},
        #                                 title="Failure in CR verifying")


        # 2) CSR has link to previous CSR
        # If prev csr id is null it means this is first time we handle this CR, thus its the first CSR
        # Check that previous CSR has not been withdrawn or paused
        # If previous_id is null this step can be ignored.
        # Else fetch previous_id from db and check the status.
        prev_csr_id_refers_to_null = crt.get_prev_record_id() == "null"
        if prev_csr_id_refers_to_null:
            debug_log.info("prev_csr_id_referred to null as it should.")
        else:
            try:
                last_csr_state = self.helpers.introspection(crt.get_cr_id_from_csr(), self.operator_url)
                if last_csr_state in ["Active", "Paused"]:
                    raise DetailedHTTPException(detail={"msg":"There is existing CR that is active,"
                                                          " before creating new CR you should change"
                                                          " status of old accordingly."})
            except LookupError as e:
                debug_log.info("Cr_id({}) doesn't have Active status in its last CSR".format(crt.get_cr_id_from_cr()))
            raise DetailedHTTPException(detail={"msg": "Verifying CSR previous_id == 'null' failed",},
                                        title="Failure in CSR verifying",
                                        status=403)


        sq.task("Store CR and CSR")
        store_dict = {
            "rs_id": crt.get_rs_id(),
            "csr_id": crt.get_csr_id(),
            "consent_status": crt.get_consent_status(),
            "previous_record_id": crt.get_prev_record_id(),
            "cr_id": crt.get_cr_id_from_cr(),
            "surrogate_id": surr_id,
            "slr_id": crt.get_slr_id(),
            "json": crt.cr["cr"]  # possibly store the base64 representation
        }
        self.helpers.storeCR_JSON(store_dict)

        # Remove unused items from dict, csr db doesn't need all of those.
        store_dict.pop("rs_id", None)
        store_dict.pop("slr_id", None)

        store_dict["json"] = crt.cr["csr"]
        debug_log.info("WORKING GAVE US: {}".format(store_dict["json"]))
        self.helpers.storeCSR_JSON(store_dict)
        if role == "Sink" and self.is_sink:
            debug_log.info("Requesting auth_token")
            get_AuthToken.delay(crt.get_cr_id_from_cr(), self.operator_url, current_app.config)
        return {"id": crt.get_cr_id_from_cr()}, 201

    @error_handler
    def patch(self):
        payload = request.json

        # Decode payload
        decoded_payload = base_token_tool.decode_payload(payload["data"]["attributes"]["payload"])

        # Create template for StoreCSR_JSON
        store_dict = {
            "csr_id": decoded_payload["record_id"],
            "consent_status": decoded_payload["consent_status"],
            "previous_record_id": decoded_payload["prev_record_id"],
            "cr_id": decoded_payload["cr_id"],
            "surrogate_id": decoded_payload["surrogate_id"],
            "json": payload["data"]["attributes"]  # possibly store the base64 representation
        }

        # Store CSR to database
        debug_log.info("BROKEN GAVE US: {}".format(store_dict["json"]))
        self.helpers.storeCSR_JSON(store_dict)

        # Forward change to Service
        # To be implemented.....


        return {"id": decoded_payload["record_id"]}, 201
        pass


api.add_resource(Install_CR, '/cr_management')


# if __name__ == '__main__':
#    app.run(debug=True, port=7000, threaded=True)
