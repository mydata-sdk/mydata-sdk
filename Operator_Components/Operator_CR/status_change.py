# -*- coding: utf-8 -*-
import logging
import traceback

from flask import Blueprint, current_app
from flask_restful import Api, Resource

from DetailedHTTPException import error_handler, DetailedHTTPException
from helpers_op import AccountManagerHandler
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
        try:
            self.AM = AccountManagerHandler(self.am_url, self.am_user, self.am_password, self.timeout)
        except Exception as e:
            debug_log.warn("Initialization of AccountManager failed. We will crash later but note it here.\n{}"
                           .format(repr(e)))
        self.helper_object = Helpers(current_app.config)

    @error_handler
    def post(self, acc_id, srv_id, cr_id, new_status):
        '''post

        :return: Change status of CR
        '''
        try:
            debug_log.info("We received status change request for cr_id ({}) for srv_id ({}) on account ({})"
                           .format(cr_id, srv_id, acc_id))
            # TODO: Do we need srv_id for anything?
            # TODO: How do we authorize this request? Who is allowed to make it?
            # Get previous_csr_id
            previous_csr = self.AM.get_last_csr(cr_id)
            previous_csr_id = previous_csr["csr_id"]
            if previous_csr["consent_status"] == new_status:
                raise DetailedHTTPException(title="Unable to change consent status from {} to {}."
                                            .format(previous_csr["consent_status"], new_status),
                                            detail={"msg": "Status change must happen from one state to another."},
                                            status=409)

            csr_payload = self.helper_object.gen_csr(acc_id, cr_id, new_status, previous_csr_id)
            debug_log.info("Created CSR payload:\n {}".format(csr_payload))
            self.AM.create_new_csr(cr_id, csr_payload)
        except AttributeError as e:
            raise DetailedHTTPException(status=502,
                                        title="It would seem initiating Account Manager Handler has failed.",
                                        detail="Account Manager might be down or unresponsive.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        return {"status": "OK"}

api.add_resource(StatusChange, '/account_id/<string:acc_id>/service/<string:srv_id>/consent/<string:cr_id>/status/<string:new_status>')
