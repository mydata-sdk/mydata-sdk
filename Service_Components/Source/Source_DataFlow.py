# -*- coding: utf-8 -*-
__author__ = 'alpaloma'

from DetailedHTTPException import error_handler
from flask import Blueprint, request, current_app
from flask_restful import Resource, Api
from helpers import Helpers, Token_tool
import logging
from jwcrypto import jwk, jwt, jws
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
        decrypted_pop_token = loads(pop_h.get_at())
        debug_log.info("Token verified state should be False here, it is: {}".format(pop_h.verified))

        debug_log.info(type(decrypted_pop_token))
        debug_log.info(dumps(decrypted_pop_token, indent=2))


        token = decrypted_pop_token["at"]["auth_token"]
        jws_holder = jwt.JWS()
        jws_holder.deserialize(raw_jws=token)
        auth_token_payload = loads(jws_holder.__dict__["objects"]["payload"])
        debug_log.info("We got auth_token_payload: {}".format(auth_token_payload))

        cr_id = auth_token_payload["pi_id"]
        debug_log.info("We got cr_id {} from auth_token_payload.".format(cr_id))

        surrogate_id = self.helpers.get_surrogate_from_cr_id(cr_id)

        cr = self.helpers.validate_cr(cr_id, surrogate_id)
        pop_key = cr["cr"]["role_specific_part"]["pop_key"]
        pop_key = jwk.JWK(**pop_key)


        token_issuer_key = cr["cr"]["role_specific_part"]["token_issuer_key"]
        token_issuer_key = jwk.JWK(**token_issuer_key)

        # Validate Token
        auth_token = jwt.JWT(jwt=token, key=token_issuer_key)

        debug_log.info("Following auth_token claims successfully verified with token_issuer_key: {}".format(auth_token.claims))

        pop_h = pop_handler(token=authorization.split(" ")[1], key=pop_key)
        decrypted_pop_token = loads(pop_h.get_at())
        debug_log.info("Token verified state should be True here, it is: {}".format(pop_h.verified))
        # Validate Request
        if pop_h.verified is False:
            raise ValueError("Request verification failed.")


        # Check that related Consent Record exists with the same rs_id # TODO: Bunch of these comments may be outdated, check them all.
        # Check that auth_token_issuer_key field of CR matches iss-field in Authorization token
        # Check Token's integrity against the signature
        # Check Token's validity period includes time of data request
        # Check Token's "aud" field includes the URI to which the data request was made
        # Token validated.

        # Validate request # TODO: Check that we fill this properly, we should though.
        # Check that request was signed with the key in the Token
        # Request validated.

        # Validate related CR # TODO: Recheck what this should hold and compare what we do.
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
