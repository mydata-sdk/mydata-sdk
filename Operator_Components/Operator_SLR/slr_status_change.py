# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import traceback
from json import loads

from flask import Blueprint, current_app, render_template_string, make_response, redirect
from flask_cors import CORS
from flask_restful import Resource, Api, request
from requests import get, post
from requests.exceptions import ConnectionError, Timeout

from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_op import Helpers, ServiceRegistryHandler, Sequences, get_am
'''

'''

# Blueprint and Flask api stuff
api_SLR_Start = Blueprint("api_SLR_change", __name__)
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
    def get(self, account_id, service_id, slr_id):
        """
        
        :param slr_id:      Id of SLR we want to change
        :param account_id:  Account Manager user id
        :param service_id:  Service id as in Service Registry
        """
        debug_log.info("#### Request to change SLR status with parameters: account_id ({}), service_id ({}), slr_id ({})"
                       .format(account_id, service_id, slr_id))

        try:
            return "WIP"
        except Exception as e:
            raise DetailedHTTPException(status=500,
                                        title="Something went really wrong during SLR registration.",
                                        detail="Error: {}".format(repr(e)),
                                        exception=e,
                                        trace=traceback.format_exc(limit=100).splitlines())

api.add_resource(StartSlrFlow, '/account/<string:account_id>/service/<string:service_id>/slr/<string:slr_id>')