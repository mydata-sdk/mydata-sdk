# -*- coding: utf-8 -*-
__author__ = 'alpaloma'

import logging
from json import loads, dumps

from flask import Blueprint, request, current_app
from flask_restful import Resource, Api
from jwcrypto import jwk, jwt

from DetailedHTTPException import error_handler
from helpers_srv import Helpers, Sequences
from signed_requests.json_builder import pop_handler

debug_log = logging.getLogger("debug")
logger = logging.getLogger("sequence")
api_Source_blueprint = Blueprint("api_Source_blueprint", __name__)
api = Api()
api.init_app(api_Source_blueprint)

sq = Sequences("Service_Components Mgmnt (Source)")
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
        self.operator_url = current_app.config["OPERATOR_URL"]  # TODO: Where do we really get this?
        self.helpers = Helpers(current_app.config)

    @error_handler
    def get(self):
        sq.task("Fetch PoP from authorization header")
        authorization = request.headers["Authorization"]
        debug_log.info(authorization)
        pop_h = pop_handler(token=authorization.split(" ")[1])  # TODO: Logic to pick up PoP, this TODO needs clarification.
        sq.task("Fetch at field from PoP")
        decoded_pop_token = loads(pop_h.get_decoded_token())
        debug_log.info("Token verified state should be False here, it is: {}".format(pop_h.verified))

        debug_log.info(type(decoded_pop_token))
        debug_log.info(dumps(decoded_pop_token, indent=2))


        sq.task("Decode auth_token from PoP and get cr_id.")
        token = decoded_pop_token["at"]["auth_token"]
        jws_holder = jwt.JWS()
        jws_holder.deserialize(raw_jws=token)
        auth_token_payload = loads(jws_holder.__dict__["objects"]["payload"])
        debug_log.info("We got auth_token_payload: {}".format(auth_token_payload))

        cr_id = auth_token_payload["pi_id"]
        debug_log.info("We got cr_id {} from auth_token_payload.".format(cr_id))

        sq.task("Fetch surrogate_id with cr_id")
        surrogate_id = self.helpers.get_surrogate_from_cr_id(cr_id)

        sq.task("Verify CR")
        cr = self.helpers.validate_cr(cr_id, surrogate_id)
        pop_key = cr["cr"]["role_specific_part"]["pop_key"]
        pop_key = jwk.JWK(**pop_key)


        token_issuer_key = cr["cr"]["role_specific_part"]["token_issuer_key"]
        token_issuer_key = jwk.JWK(**token_issuer_key)

        sq.task("Validate auth token")
        auth_token = jwt.JWT(jwt=token, key=token_issuer_key)

        debug_log.info("Following auth_token claims successfully verified with token_issuer_key: {}".format(auth_token.claims))

        sq.task("Validate Request(PoP token)")
        pop_h = pop_handler(token=authorization.split(" ")[1], key=pop_key)
        decoded_pop_token = loads(pop_h.get_decoded_token())  # This step affects verified state of object.
        debug_log.info("Token verified state should be True here, it is: {}".format(pop_h.verified))
        # Validate Request
        if pop_h.verified is False:
            raise ValueError("Request verification failed.")

        try:
            sq.task("Intropection")
            status_of_last_csr = self.helpers.introspection(cr_id, self.operator_url)
            if status_of_last_csr == "Active":
                # Process request
                sq.task("Return requested data.")
                # This is where the data requested gets fetched and returned.
                return {"Some test data": "like so", "and it continues": "like so!"}
            else:
                # TODO Write somewhere that this returns status of last csr source has verified to Sink
                debug_log.info("Status of last csr is: {}".format(status_of_last_csr))
                return {"error message is": "appropriate.", "csr_status": status_of_last_csr}

        except LookupError as e:
            debug_log.exception(e)
            return {"error message is": "appropriate."}

        # Return.

api.add_resource(DataRequest, '/datarequest')
api.add_resource(Status, '/init')

