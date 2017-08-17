# -*- coding: utf-8 -*-
import logging
import traceback
from json import dumps

from flask import Blueprint, current_app, request
from flask_restful import Api, Resource

from DetailedHTTPException import error_handler, DetailedHTTPException
from helpers_op import Helpers, Sequences, get_am, api_logging

# Init Flask
api_CR_blueprint = Blueprint("api_AuthToken", __name__)
api = Api()
api.init_app(api_CR_blueprint)

# Logging
debug_log = logging.getLogger("debug")
sq = Sequences("Operator_Components Mgmnt")


class AuthToken(Resource):
    def __init__(self):
        super(AuthToken, self).__init__()
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]
        helper_object = Helpers(current_app.config)
        self.gen_auth_token = helper_object.gen_auth_token

    @error_handler
    @api_logging
    def get(self, cr_id):
        '''get

        :return: Returns Auth_token to service
        '''
        ##
        # Generate Auth Token and save it.
        # helper.py has the function template, look into it.
        ##
        am = get_am(current_app, request.headers)
        try:
            result = am.get_AuthTokenInfo(cr_id)
        except AttributeError as e:
            raise DetailedHTTPException(status=502,
                                        title="It would seem initiating Account Manager Handler has failed.",
                                        detail="Account Manager might be down or unresponsive.",
                                        trace=traceback.format_exc(limit=100).splitlines())
        debug_log.info("Account Manager gave following Auth Token Info:\n{}".format(dumps(result, indent=2)))
        token = self.gen_auth_token(result)
        debug_log.info("Generated auth token: {}".format(token))
        return {"auth_token": token}


api.add_resource(AuthToken, '/auth_token/<string:cr_id>')