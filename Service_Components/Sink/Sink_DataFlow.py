# -*- coding: utf-8 -*-
from flask import current_app

from helpers import Helpers

__author__ = 'alpaloma'

from DetailedHTTPException import error_handler
from flask import Blueprint
from flask_restful import Resource, Api

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
    def get(self, user_id, cr_id, rs_id):

        # Get data_set_id fromm query param
        data_set_id = request.args.get("data_set_id")

        # Create request
        request = {"we want": "data"}

        # Validate CR
        # Check integrity (signature)
        # Check that state is "Active"
        # Check "Issued" timestamp
        # Check "Not Before" timestamp
        # Check "Not After" timestamp
        # CR validated.

        # Validate Request from UI
        # Check that rs_description field contains rs_id
        # Check that rs_description field contains data_set_id (Optional?)
        # Request from UI validated.

        # Fetch data request urls
        # LOOP: for every data_set_id
            # Fetch corresponding distrubution point url based on data_set_id
        # Data request urls fetched.

        # Validate Authorisation Token
        # Fetch Authorisation Token related CR from data storage by rs_id
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
        self.helpers.validate_cr(cr_id)
        status = {"status": "running", "service_mode": "Sink"}
        return status



api.add_resource(Status, '/init')
api.add_resource(DataFlow, ' /user/<user_id>/consentRecord/<cr_id>/resourceSet/<rs_id>')
