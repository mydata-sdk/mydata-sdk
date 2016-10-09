# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
from flask import Blueprint, current_app, request
from helpers import Helpers
from DetailedHTTPException import error_handler
from flask_restful import Resource, Api
import logging
debug_log = logging.getLogger("debug")
api_Sink_blueprint = Blueprint("api_Sink_blueprint", __name__)
api = Api()
api.init_app(api_Sink_blueprint)

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
        status = {"status": "running", "service_mode": "Sink"}
        return status

class DataFlow(Resource):
    def __init__(self):
        super(DataFlow, self).__init__()
        self.service_url = current_app.config["SERVICE_URL"]
        self.helpers = Helpers(current_app.config)

    @error_handler
    def post(self):  # TODO Make this a GET
        params = request.json
        debug_log.info(params)
        debug_log.info(request.json)
        user_id = params["user_id"]
        cr_id = params["cr_id"]
        rs_id = params["rs_id"]
        # Get data_set_id fromm query param
        data_set_id = request.args.get("data_set_id", None)
        debug_log.info("data_set_id is ({}), cr_id is ({}), user_id ({}) and rs_id ({})"
                       .format(data_set_id, cr_id, user_id, rs_id))
        # Create request
        req = {"we want": "data"}

        # Validate CR
        cr = self.helpers.validate_cr(cr_id, surrogate_id=user_id)

        # Validate Request from UI
        distribution_ids = self.helpers.validate_request_from_ui(cr, data_set_id, rs_id)

        # Fetch data request urls
        # LOOP: for every data_set_id
        for distribution_id in distribution_ids:
            debug_log.info(distribution_id)
            # Fetch corresponding distrubution point url based on data_set_id
            pass  # TODO: Implement

        # Data request urls fetched.
        debug_log.info("Data request urls fetched.")

        # Validate Authorisation Token
        surrogate_id = cr["cr"]["common_part"]["surrogate_id"]
        self.helpers.validate_authorization_token(cr_id, surrogate_id)
        # Fetch Authorisation Token related to CR from data storage by rs_id (cr_id?)

        token = self.helpers.get_token(cr_id)
        debug_log.info(token)
        # Check Integrity ( Signed by operator, Operator's public key can be found from SLR)

        # Check that "sub" contains correct public key (operators, sources?)
        # Check "Issued" timestamp
        # Check "Not Before" timestamp
        # Check "Not After" timestamp

        # OPT: Token expired
        # Get new Authorization token, start agian from validation.

        # Check URL patterns in "aud" field
        # Check that fetched distribution urls can be found from "aud" field

        # Token validated
        # With these two steps Sink has verified that it's allowed to make request.

        # Construct request
        # Select request URL from "aud" field
        # Add Authorisation Token to request
        # Request constructed.

        # Sign request
        # Fetch private key pair of public key specified in Authorisation Token's "sub" field.
        # Sign with fetched private key
        # Sign with fetched private key
        # Add signature to request
        # Request signed.
        # Request created.

        # Make Data Request

        status = {"status": "running", "service_mode": "Sink"}
        return status



api.add_resource(Status, '/init')
api.add_resource(DataFlow, '/dc')

#api.add_resource(DataFlow, '/user/<string:user_id>/consentRecord/<string:cr_id>/resourceSet/<string:rs_id>')

#"http://service_components:7000/api/1.2/sink_flow/user/95479a08-80cc-4359-ba28-b8ca23ff5572_53af88dc-33de-44be-bc30-e0826db9bd6c/consentRecord/cd431509-777a-4285-8211-95c5ac577537/resourceSet/http%3A%2F%2Fservice_components%3A7000%7C%7C9aebb487-0c83-4139-b12c-d7fcea93a3ad"