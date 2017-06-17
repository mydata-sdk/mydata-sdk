# -*- coding: utf-8 -*-
import logging
import traceback

from flask import Blueprint, current_app, request
from flask_restful import Api, Resource

from DetailedHTTPException import error_handler, DetailedHTTPException
from helpers_op import get_am
from helpers_op import Helpers

# Init Flask
api_CR_blueprint = Blueprint("api_Status_Change_blueprint", __name__)
api = Api()
api.init_app(api_CR_blueprint)

# Logging
debug_log = logging.getLogger("debug")


class StatusChange(Resource):
    def __init__(self):
        super(StatusChange, self).__init__()
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]
        self.helper_object = Helpers(current_app.config)

    @error_handler
    def post(self, acc_id, srv_id, cr_id, new_status):
        '''post

        :return: Change status of CR
        '''
        try:
            allowed_states = ["Active", "Disabled", "Withdrawn"]
            if new_status in allowed_states:
                debug_log.info("We received status change request for cr_id ({}) for srv_id ({}) on account ({})"
                               .format(cr_id, srv_id, acc_id))
                # How do we authorize this request? Who is allowed to make it?
                # Now only those who have Account User Key can successfully make this.
                # Get previous_csr_id

                am = get_am(current_app, request.headers)
                key_check = am.verify_user_key(acc_id)
                debug_log.info("Verifying User Key resulted: {}".format(key_check))
                link_id, surrogate_id = am.get_surrogate_and_slr_id(acc_id, srv_id)
                previous_csr = am.get_last_csr(cr_id, link_id)
                previous_csr_id = previous_csr["record_id"]
                previous_status = previous_csr["consent_status"]
                if previous_status == new_status:
                    raise DetailedHTTPException(title="Unable to change consent status from {} to {}."
                                                .format(previous_csr["consent_status"], new_status),
                                                detail={"msg": "Status change must happen from one state to another."},
                                                status=409)
                elif previous_status == "Withdrawn":
                    raise DetailedHTTPException(title="Unable to change consent status from {} to {}."
                                                .format(previous_csr["consent_status"], new_status),
                                                detail={"msg": "Status change to Withdrawn is final."},
                                                status=409)

                csr_payload = self.helper_object.gen_csr(surrogate_id, cr_id, new_status, previous_csr_id)
                debug_log.info("Created CSR payload:\n {}".format(csr_payload))
                csr = am.create_new_csr(cr_id, csr_payload)
            else:
                raise DetailedHTTPException(title="Unable to change consent status to {}.".format(new_status),
                                            detail={"msg": "Unsupported Status Change"},
                                            status=409)
        except Exception as e:
            raise DetailedHTTPException(status=500,
                                        title="Consent Status Change Failed.",
                                        detail="Server encountered unexpected error while trying consent status change,"
                                               " please try again.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        return csr, 201

api.add_resource(StatusChange, '/account_id/<string:acc_id>/service/<string:srv_id>/consent/<string:cr_id>/status/<string:new_status>')
