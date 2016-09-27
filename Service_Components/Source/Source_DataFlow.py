# -*- coding: utf-8 -*-
__author__ = 'alpaloma'

from DetailedHTTPException import error_handler
from flask import Blueprint
from flask_restful import Resource, Api

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
    @error_handler
    def get(self):

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
