# -*- coding: utf-8 -*-
import logging
import traceback
from json import dumps

from flask import Blueprint, current_app, request
from flask_restful import Api, Resource

from DetailedHTTPException import error_handler, DetailedHTTPException
from helpers_op import api_logging, get_am, Sequences

# Init Flask
api_CR_blueprint = Blueprint("api_Introspection", __name__)
api = Api()
api.init_app(api_CR_blueprint)

# Logging
debug_log = logging.getLogger("debug")
sq = Sequences("OpMgmt")

class Introspection(Resource):
    def __init__(self):
        super(Introspection, self).__init__()
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]

    @error_handler
    @api_logging
    def get(self, cr_id):
        '''post

        :return: Returns latest csr id for source
        '''
        try:
            debug_log.info("We received request for latest csr id for cr_id ({})".format(cr_id))
            result = self.AM.get_last_csr(cr_id)
        except AttributeError as e:
            raise DetailedHTTPException(status=502,
                                        title="It would seem initiating Account Manager Handler has failed.",
                                        detail="Account Manager might be down or unresponsive.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        debug_log.info("Latest csr id for given cr_id is: ".format(result["csr_id"]))
        return result


class IntrospectionMissing(Resource):
    def __init__(self):
        super(IntrospectionMissing, self).__init__()
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]
        try:
            self.AM = AccountManagerHandler(self.am_url, self.am_user, self.am_password, self.timeout)
        except Exception as e:
            debug_log.warn("Initialization of AccountManager failed. We will crash later but note it here.\n{}"
                           .format(repr(e)))

    @error_handler
    @api_logging
    def get(self, cr_id, csr_id):
        """get

        :return: Returns latest csr for source
        """
        try:
            debug_log.info("We received introspection request for cr_id ({})".format(cr_id))
            result = self.AM.get_missing_csr(cr_id, csr_id)
        except AttributeError as e:
            raise DetailedHTTPException(status=502,
                                        title="It would seem initiating Account Manager Handler has failed.",
                                        detail="Account Manager might be down or unresponsive.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        debug_log.info(dumps(result))
        return result

api.add_resource(Introspection, '/introspection/<string:cr_id>')
api.add_resource(IntrospectionMissing, '/consent/<string:cr_id>/missing_since/<string:csr_id>')
