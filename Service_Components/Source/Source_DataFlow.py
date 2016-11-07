# -*- coding: utf-8 -*-
__author__ = 'alpaloma'

from DetailedHTTPException import error_handler
from flask import Blueprint, request, current_app
from flask_restful import Resource, Api
from helpers import Helpers
import logging
from jwcrypto import jwk
from json import loads, dumps
from signed_requests.json_builder import pop_handler
debug_log = logging.getLogger("debug")
api_Source_blueprint = Blueprint("api_Source_blueprint", __name__)
api = Api()
api.init_app(api_Source_blueprint)


# import xmltodict
# @api.representation('application/xml')
# def output_xml(data, code, headers=None):
#     if isinstance(data, dict):
#         xm = {"response": data}
#         resp = make_response(xmltodict.unparse(xm, pretty=True), code)
#         resp.headers.extend(headers)
#         return resp

class Status(Resource):
    @error_handler
    def get(self):
        status = {"status": "running", "service_mode": "Source"}
        return status

class DataRequest(Resource):
    def __init__(self):
        super(DataRequest, self).__init__()
        self.service_url = current_app.config["SERVICE_URL"]
        self.helpers = Helpers(current_app.config)

    @error_handler
    def get(self):
        authorization = request.headers["Authorization"]
        debug_log.info(authorization)
        pop_h = pop_handler(token=authorization.split(" ")[1])
        decrypted_token = loads(pop_h.get_at())
        debug_log.info("Token verified state: {}".format(pop_h.verified))

        debug_log.info(type(decrypted_token))
        debug_log.info(dumps(decrypted_token, indent=2))
        cr_id = decrypted_token["at"]["pi_id"]
        debug_log.info("got cr_id {}".format(decrypted_token["at"]["pi_id"]))

        surrogate_id = self.helpers.get_surrogate_from_cr_id(cr_id)

        cr = self.helpers.validate_cr(cr_id, surrogate_id)
        pop_key = cr["cr"]["role_specific_part"]["pop_key"]
        pop_key = jwk.JWK(**pop_key)
        pop_h = pop_handler(token=authorization.split(" ")[1], key=pop_key)
        decrypted_token = loads(pop_h.get_at())
        debug_log.info("Token verified state: {}".format(pop_h.verified))
        if pop_h.verified is False:
            raise ValueError("Request verification failed.")




        # Validate Request
        # Validate Token
        # Check that related Consent Record exists with the same rs_id
        # Check that auth_token_issuer_key field of CR matches iss-field in Authorization token
        # Check Token's integrity against the signature
        # Check Token's validity period includes time of data request
        # Check Token's "aud" field includes the URI to which the data request was made
        # Token validated.

        # Validate request
        # Check that request was signed with the key in the Token
        # Request validated.

        # Validate related CR
        # Validate the related Consent Record as defined in MyData Authorisation Specification
        # CR Validated.

        # OPT: Introspection
        # GET Consent Record Status (source_cr_id)

        # Process request
        # Return.

        status = {"status": "running", "service_mode": "Source"}
        return status

api.add_resource(DataRequest, '/datarequest')
api.add_resource(Status, '/init')
