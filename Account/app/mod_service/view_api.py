# -*- coding: utf-8 -*-

"""
__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

# Import dependencies
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom
from random import randint

# Import flask dependencies
import time
from flask import Blueprint, render_template, make_response, flash, session, request, jsonify, url_for, json, current_app
from flask_login import login_user, login_required
from flask_restful import Resource, Api, reqparse
from base64 import b64decode

# Import services
from app.helpers import get_custom_logger, make_json_response, ApiError, validate_json, compare_str_ids
from app.mod_account.controllers import verify_account_id_match
from app.mod_api_auth.controllers import requires_api_auth_user, get_account_id_by_api_key, provide_api_key, \
    requires_api_auth_sdk, get_user_api_key, get_sdk_api_key
from app.mod_blackbox.controllers import sign_jws_with_jwk, generate_and_sign_jws, get_account_public_key, \
    verify_jws_signature_with_jwk
from app.mod_database.helpers import get_db_cursor
from app.mod_database.models import ServiceLinkRecord, ServiceLinkStatusRecord
from app.mod_service.controllers import sign_slr, store_slr_and_ssr, sign_ssr, get_surrogate_id_by_account_and_service, \
    init_slr_sink, init_slr_source, get_slr_record
from app.mod_service.models import NewServiceLink, VerifyServiceLink
from app.mod_service.schemas import schema_sl_init_sink, schema_sl_init_source, schema_sl_sign

mod_service_api = Blueprint('service_api', __name__, template_folder='templates')
api = Api(mod_service_api)

# create logger with 'spam_application'
logger = get_custom_logger(__name__)


# Resources
class ServiceLinkInitSource(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def post(self, account_id):
        try:
            endpoint = str(api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        try:
            account_id = str(account_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported account_id", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Account ID from path: " + account_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # load JSON
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        validate_json(json_data, schema_sl_init_source)

        # Get elements from payload
        try:
            code = str(json_data['code'])
            slr_id = json_data['data']['attributes']['slr_id']
        except Exception as exp:
            error_title = "Could not get data from payload"
            logger.error(error_title + ": " + str(exp.message))
            raise ApiError(code=500, title="Could not fetch code from json", detail=str(exp.message), source=endpoint)
        else:
            logger.debug("code from payload: " + code)
            logger.debug("slr_id from payload: " + slr_id)

        try:
            slr_id_inited = init_slr_source(account_id=account_id, slr_id=slr_id, endpoint=endpoint)
        except ApiError as exp:
            logger.error(repr(exp))
            raise
        except Exception as exp:
            error_title = "Could not initialize service link"
            logger.error(error_title + ": " + str(exp.message))
            raise ApiError(code=500, title="Could not fetch code from json", detail=repr(exp), source=endpoint)

        # Response data container
        try:
            response_data = {
                "code": code,
                "data": {
                    "attributes": {
                        "slr_id": slr_id_inited
                    }
                }
            }
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data, status_code=201)


class ServiceLinkInitSink(Resource):
    @requires_api_auth_sdk
    @requires_api_auth_user
    def post(self, account_id):
        try:
            endpoint = str(api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        try:
            account_id = str(account_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported account_id", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Account ID from path: " + account_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # load JSON
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        validate_json(json_data, schema_sl_init_sink)

        # Get elements from payload
        try:
            code = str(json_data['code'])
            pop_key = json_data['data']['attributes']['pop_key']
            slr_id = json_data['data']['attributes']['slr_id']
        except Exception as exp:
            error_title = "Could not get data from payload"
            logger.error(error_title + ": " + str(exp.message))
            raise ApiError(code=500, title="Could not fetch code from json", detail=str(exp.message), source=endpoint)
        else:
            logger.debug("code from payload: " + code)
            logger.debug("slr_id from payload: " + slr_id)
            logger.debug("pop_key from payload: " + json.dumps(pop_key))

        try:
            slr_id_inited = init_slr_sink(account_id=account_id, slr_id=slr_id, pop_key=pop_key, endpoint=endpoint)
        except ApiError as exp:
            logger.error(repr(exp))
            raise
        except Exception as exp:
            error_title = "Could not initialize service link"
            logger.error(error_title + ": " + str(exp.message))
            raise ApiError(code=500, title="Could not fetch code from json", detail=repr(exp), source=endpoint)

        # Response data container
        try:
            response_data = {
                "code": code,
                "data": {
                    "attributes": {
                        "slr_id": slr_id_inited
                    }
                }
            }
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class ServiceLinkSign(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def patch(self, account_id, link_id):
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        try:
            account_id = str(account_id)
            link_id = str(link_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported path variables", detail=repr(exp), source=endpoint)
        else:
            logger.debug("account_id from path: " + account_id)
            logger.debug("link_id from path: " + link_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # load JSON
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        validate_json(json_data, schema_sl_sign)

        # Get elements from payload
        try:
            logger.info("Get elements from payload")
            code = str(json_data['code'])
            slr_payload = json_data['data']['attributes']
            link_id_from_payload = str(json_data['data']['attributes']['link_id'])
        except Exception as exp:
            error_title = "Could not get data from payload"
            logger.error(error_title + ": " + str(exp.message))
            raise ApiError(code=500, title="Could not get elements from payload", detail=str(exp.message), source=endpoint)
        else:
            logger.debug("code from payload: " + code)
            logger.debug("slr_payload from payload: " + json.dumps(slr_payload))
            logger.debug("link_id_from_payload from payload: " + link_id_from_payload)

        # Verify SLR IDs from path and payload are matching
        try:
            compare_str_ids(id=link_id, id_to_compare=link_id_from_payload)
        except ValueError as exp:
            error_title = "SLR IDs from path and payload are not matching"
            error_detail = "SLR ID from path was {} and from payload {}".format(link_id, link_id_from_payload)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("SLR IDs from path and payload are not matching")

        # Get inited ServiceLinkRecord object
        try:
            logger.info("Get inited ServiceLinkRecord object")
            slr_inited = get_slr_record(account_id=account_id, slr_id=link_id, endpoint=endpoint)
        except IndexError as exp:
            error_title = "Could not find inited ServiceLinkRecord object with provided information"
            error_detail = "ServiceLinkRecord was searched with link_id: {} and account_id {}".format(link_id, account_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=404, title=error_title, detail=str(exp.message), source=endpoint)
        except Exception as exp:
            error_title = "Could not get inited ServiceLinkRecord object"
            error_detail = "ServiceLinkRecord was searched with link_id: {} and account_id {}".format(link_id, account_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("Got inited ServiceLinkRecord object")
            logger.debug("slr_inited: " + slr_inited.log_entry)

        # Sign SLR
        try:
            slr_signed_dict = sign_slr(account_id=account_id, slr_payload=slr_payload, endpoint=str(endpoint))
        except Exception as exp:
            logger.error("Could not sign SLR: " + repr(exp))
            raise

        # Response data container
        try:
            response_data = {
              "code": "string",
              "data": {
                "type": "ServiceLinkRecord",
                "id": link_id,
                "attributes": slr_signed_dict
              }
            }
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class ServiceLinkStore(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def post(self, account_id):

        try:
            endpoint = str(api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            api_key = request.headers.get('Api-Key')
        except Exception as exp:
            logger.error("No ApiKey in headers")
            logger.debug("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)

        try:
            account_id = str(account_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported account_id", detail=repr(exp), source=endpoint)

        # load JSON
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = VerifyServiceLink()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors), source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        ######
        # SLR
        ######
        #
        # Get slr
        try:
            slr = json_data['data']['slr']['attributes']['slr']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch slr from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got slr: " + json.dumps(slr))

        # Get surrogate_id
        try:
            surrogate_id = json_data['data']['surrogate_id']['attributes']['surrogate_id']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch surrogate id from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got surrogate_id: " + str(surrogate_id))

        # Decode slr payload
        try:
            #print (json.dumps(json_data))
            slr_payload_encoded = slr['payload']
            slr_payload_encoded += '=' * (-len(slr_payload_encoded) % 4)  # Fix incorrect padding, base64
            slr_payload_decoded = b64decode(slr_payload_encoded).replace('\\', '').replace('"{', '{').replace('}"', '}')
            slr_payload_dict = json.loads(slr_payload_decoded)
        except Exception as exp:
            raise ApiError(code=400, title="Could not decode slr payload", detail=repr(exp), source=endpoint)
        else:
            logger.debug("slr_payload_decoded: " + str(slr_payload_decoded))

        # Get service_link_record_id
        try:
            slr_id = slr_payload_dict['link_id']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch service link record id from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got slr_id: " + str(slr_id))

        # Get service_id
        try:
            service_id = slr_payload_dict['service_id']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch service id from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got service_id: " + str(service_id))

        # Get operator_id
        try:
            operator_id = slr_payload_dict['operator_id']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch operator id from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got operator_id: " + str(operator_id))

        #######
        # Ssr
        #######
        #
        # Get ssr payload
        try:
            ssr_payload = json_data['data']['ssr']['attributes']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch ssr from json", detail=repr(exp), source=endpoint)

        # Get ssr_id
        try:
            ssr_id = ssr_payload['record_id']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch record_id from ssr_payload", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got ssr_id: " + str(ssr_id))

        # Get ssr_status
        try:
            ssr_status = ssr_payload['sl_status']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch sl_status from ssr_payload", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got ssr_status: " + str(ssr_status))

        # Get slr_id_from_ssr
        try:
            slr_id_from_ssr = ssr_payload['slr_id']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch slr_id from ssr_payload", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got slr_id: " + str(slr_id))

        # Get prev_ssr_id
        try:
            prev_ssr_id = ssr_payload['prev_record_id']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch prev_ssr_id from ssr_payload", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got prev_ssr_id: " + str(prev_ssr_id))

        # Get iat
        try:
            ssr_iat = int(ssr_payload['iat'])
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch iat from ssr_payload", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got iat: " + str(prev_ssr_id))

        #
        # Get code
        try:
            code = json_data['code']
        except Exception as exp:
            raise ApiError(code=400, title="Could not fetch code from json", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Got code: " + str(code))

        ##
        ##
        # Check that slr and ssr payload are matching # TODO: Jatka slr:n ja ssr:n keskinäistä vertailua ja validointia
        if not slr_id == slr_id_from_ssr:
            detail_data = {'slr_id': str(slr_id), 'slr_id_from_ssr': str(slr_id_from_ssr)}
            raise ApiError(code=409, title="Service Link Record ID's are not matching", detail=detail_data, source=endpoint)

        ##
        ##
        # Verify Account owner's signature in Service Link Record
        try:
            slr_verified = verify_jws_signature_with_jwk(account_id=account_id, jws_json_to_verify=json.dumps(slr))
        except Exception as exp:
            logger.error("Could not verify Account owner's signature in Service Link Record: " + repr(exp))
            raise ApiError(code=500, title="Failed to verify Account owner's signature in Service Link Record", detail=repr(exp), source=endpoint)
        else:
            logger.info('Service Link Record verified')
            logger.info('Verification passed: ' + str(slr_verified))

        # Sign Ssr
        try:
            ssr_signed = sign_ssr(account_id=account_id, ssr_payload=ssr_payload, endpoint=str(endpoint))
        except Exception as exp:
            logger.error("Could not sign Ssr")
            logger.debug("Could not sign Ssr: " + repr(exp))
            raise


        # Store slr and ssr
        logger.info("Storing Service Link Record and Service Link Status Record")
        try:
            slr_entry = ServiceLinkRecord(
                service_link_record=slr,
                service_link_record_id=slr_id,
                service_id=service_id,
                surrogate_id=surrogate_id,
                operator_id=operator_id,
                account_id=account_id
            )
        except Exception as exp:
            logger.error('Could not create Service Link Record object: ' + repr(exp))
            raise ApiError(code=500, title="Failed to create Service Link Record object", detail=repr(exp), source=endpoint)

        try:
            ssr_entry = ServiceLinkStatusRecord(
                service_link_status_record_id=ssr_id,
                status=ssr_status,
                service_link_status_record=ssr_signed,
                service_link_record_id=slr_id_from_ssr,
                issued_at=ssr_iat,
                prev_record_id=prev_ssr_id
            )
        except Exception as exp:
            logger.error('Could not create Service Link Status Record object: ' + repr(exp))
            raise ApiError(code=500, title="Failed to create Service Link Status Record object", detail=repr(exp), source=endpoint)

        try:
            stored_slr_entry, stored_ssr_entry = store_slr_and_ssr(slr_entry=slr_entry, ssr_entry=ssr_entry, endpoint=str(endpoint))
        except Exception as exp:
            logger.error("Could not store Service Link Record and Service Link Status Record")
            logger.debug("Could not store SLR and Ssr: " + repr(exp))
            raise
        else:
            logger.info("Stored Service Link Record and Service Link Status Record")
            logger.debug("stored_slr_entry: " + stored_slr_entry.log_entry)
            logger.debug("stored_ssr_entry: " + stored_ssr_entry.log_entry)

        # Response data container
        try:
            response_data = {}
            response_data['code'] = code

            response_data['data'] = {}

            response_data['data']['slr'] = stored_slr_entry.to_record_dict

            response_data['data']['ssr'] = stored_ssr_entry.to_record_dict

            response_data['data']['surrogate_id'] = surrogate_id
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class ServiceSurrogate(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, service_id):

        try:
            endpoint = str(api.url_for(self, account_id=account_id, service_id=service_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            api_key = request.headers.get('Api-Key')
        except Exception as exp:
            logger.error("No ApiKey in headers")
            logger.debug("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)

        try:
            account_id = str(account_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported account_id", detail=repr(exp), source=endpoint)

        try:
            service_id = str(service_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported service_id", detail=repr(exp), source=endpoint)

        try:
            surrogate_id = get_surrogate_id_by_account_and_service(account_id=account_id, service_id=service_id, endpoint=endpoint)
        except IndexError as exp:
            raise ApiError(code=404, title="Nothing could not be found with provided information", detail=repr(exp), source=endpoint)
        except Exception as exp:
            logger.error('Could not get surrogate_id: ' + repr(exp))
            raise ApiError(code=500, title="Could not get surrogate_id", detail=repr(exp), source=endpoint)
        else:
            logger.debug('Got surrogate_id: ' + repr(surrogate_id))

        # Response data container
        try:
            response_data = {}
            response_data['data'] = {}

            response_data['data']['surrogate_id'] = {}
            response_data['data']['surrogate_id']['type'] = "SurrogateId"
            response_data['data']['surrogate_id']['attributes'] = surrogate_id
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)



# Register resources
api.add_resource(ServiceLinkInitSource, '/accounts/<string:account_id>/servicelinks/init/source/', endpoint='sl_init_source')
api.add_resource(ServiceLinkInitSink, '/accounts/<string:account_id>/servicelinks/init/sink/', endpoint='sl_init_sink')
api.add_resource(ServiceLinkSign, '/accounts/<string:account_id>/servicelinks/<string:link_id>/', endpoint='sl_sign')
api.add_resource(ServiceLinkStore, '/accounts/<string:account_id>/servicelinks/verify/', endpoint='sl_verify')
api.add_resource(ServiceSurrogate, '/accounts/<string:account_id>/services/<string:service_id>/surrogate/', endpoint='surrogate_id')  # TODO: Is this needed?

