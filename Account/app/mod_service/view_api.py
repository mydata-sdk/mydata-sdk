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

# Import dependencies
from _mysql_exceptions import IntegrityError
from flask import Blueprint, request, json
from flask_restful import Resource, Api
from base64 import b64decode
from app.helpers import get_custom_logger, make_json_response, ApiError, validate_json, compare_str_ids
from app.mod_account.controllers import verify_account_id_match
from app.mod_api_auth.controllers import requires_api_auth_user, requires_api_auth_sdk, get_user_api_key, get_sdk_api_key
from app.mod_blackbox.controllers import verify_jws_signature_with_jwk
from app.mod_database.models import ServiceLinkStatusRecord
from app.mod_service.controllers import sign_slr, store_slr_and_ssr, sign_ssr, init_slr_sink, init_slr_source, \
    get_slr_record, get_slrs, get_slr, get_slsrs, get_slsr, get_last_slr_status, get_slrs_for_service, \
    get_slr_for_service, store_ssr, get_surrogate_id_by_account_and_service, get_account_id_by_service_and_surrogate_id
from app.mod_service.schemas import schema_sl_init_sink, schema_sl_init_source, schema_sl_sign, schema_sl_store, \
    schema_sls_to_sign_by_account, schema_sls_signed_by_operator

mod_service_api = Blueprint('service_api', __name__, template_folder='templates')
api = Api(mod_service_api)

# create logger with 'spam_application'
logger = get_custom_logger(__name__)


# Resources
class ApiServiceLinkInitSource(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def post(self, account_id):
        """
        Stores Service Link ID to Account

        :param account_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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


class ApiServiceLinkInitSink(Resource):
    @requires_api_auth_sdk
    @requires_api_auth_user
    def post(self, account_id):
        """
        Stores Service Link ID to Account with PoP Key.

        :param account_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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


class ApiServiceLink(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id):
        """
        Fetch Service Link Record by Service Link ID

        :param account_id:
        :param slr_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("link_id: " + link_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkRecord
        try:
            logger.info("Fetching ServiceLinkRecord")
            db_entries = get_slr(account_id=account_id, slr_id=link_id)
        except IndexError as exp:
            error_title = "No ServiceLinkRecord found"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No ServiceLinkRecord found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("ServiceLinkRecord Fetched")

        # Response data container
        try:
            response_data = {}
            response_data['data'] = db_entries
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


    @requires_api_auth_user
    @requires_api_auth_sdk
    def patch(self, account_id, link_id):
        """
        Signs constructed Service Link Record with Account owner’s key.

        :param account_id:
        :param link_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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
            logger.info("SLR IDs from path and payload are matching")

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


class ApiServiceLinkStore(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def post(self, account_id, link_id):
        """
        Verifies the integrity of provided Service Link Record.
        If verification passes Service Link Status Record is constructed and signed with Account owner’s key.
        Finally both records are stored.

        :param account_id:
        :param link_id:
        :return: JSON object
        """

        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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
        validate_json(json_data, schema_sl_store)

        # Get elements from payload
        try:
            logger.info("Get elements from payload")
            code = str(json_data['code'])
            link_id_from_payload = str(json_data['data']['slr']['id'])
            slr = json_data['data']['slr']['attributes']
            ssr_payload_dict = json_data['data']['ssr']['attributes']
        except Exception as exp:
            error_title = "Could not get data from request payload"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("code from payload: " + code)
            logger.debug("slr from payload: " + json.dumps(slr))
            logger.debug("link_id_from_payload from payload: " + link_id_from_payload)
            logger.debug("ssr payload from payload: " + json.dumps(ssr_payload_dict))

        # Verify SLR IDs from path and payload are matching
        try:
            compare_str_ids(id=link_id, id_to_compare=link_id_from_payload)
        except ValueError as exp:
            error_title = "SLR IDs from path and payload are not matching"
            error_detail = "SLR ID from path was {} and from payload {}".format(link_id, link_id_from_payload)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("SLR IDs from path and payload are matching")
            logger.debug("SLR ID from path was {} and from payload {}".format(link_id, link_id_from_payload))

        # Decode slr payload
        try:
            logger.info("Decoding base64 payload")
            #print (json.dumps(json_data))
            slr_payload_encoded = slr['payload']
            slr_payload_encoded += '=' * (-len(slr_payload_encoded) % 4)  # Fix incorrect padding, base64
            slr_payload_decoded = b64decode(slr_payload_encoded).replace('\\', '').replace('"{', '{').replace('}"', '}')
            slr_payload_dict = json.loads(slr_payload_decoded)
        except Exception as exp:
            error_title = "Could not decode Service Link Record payload"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("SLR payload decoded")
            logger.debug("slr: " + json.dumps(slr))
            logger.debug("slr_payload_decoded: " + json.dumps(slr_payload_dict))

        # Get link_id_from_slr
        try:
            link_id_from_slr = slr_payload_dict['link_id']
        except Exception as exp:
            error_title = "Could not fetch service link record id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got link_id_from_slr: " + str(link_id_from_slr))

        # Verify SLR IDs from path and signed slr are matching
        try:
            compare_str_ids(id=link_id, id_to_compare=link_id_from_slr)
        except ValueError as exp:
            error_title = "SLR IDs from path and signed slr are not matching"
            error_detail = "SLR ID from path was {} and from signed slr {}".format(link_id, link_id_from_payload)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("SLR IDs from path and signed slr are not matching")

        # Get service_id
        try:
            service_id = slr_payload_dict['service_id']
        except Exception as exp:
            error_title = "Could not fetch service_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got service_id: " + str(service_id))

        # Get operator_id
        try:
            operator_id = slr_payload_dict['operator_id']
        except Exception as exp:
            error_title = "Could not fetch operator_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got operator_id: " + str(operator_id))

        # Get surrogate_id
        try:
            surrogate_id_from_slr = slr_payload_dict['surrogate_id']
        except Exception as exp:
            error_title = "Could not fetch surrogate_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got surrogate_id_from_slr: " + str(surrogate_id_from_slr))

        # Get ssr_id
        try:
            ssr_id = ssr_payload_dict['record_id']
        except Exception as exp:
            error_title = "Could not fetch record_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got ssr_id: " + str(ssr_id))

        # Get ssr_status
        try:
            ssr_status = ssr_payload_dict['sl_status']
        except Exception as exp:
            error_title = "Could not fetch sl_status from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got ssr_status: " + str(ssr_status))

        # Get slr_id_from_ssr
        try:
            link_id_from_ssr = ssr_payload_dict['slr_id']
        except Exception as exp:
            error_title = "Could not fetch link_id_from_ssr from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got link_id_from_ssr: " + str(link_id_from_ssr))

        # Get prev_ssr_id
        try:
            prev_ssr_id = ssr_payload_dict['prev_record_id']
        except Exception as exp:
            error_title = "Could not fetch prev_ssr_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got prev_ssr_id: " + str(prev_ssr_id))

        # Get iat
        try:
            ssr_iat = int(ssr_payload_dict['iat'])
        except Exception as exp:
            error_title = "Could not fetch iat from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got iat: " + str(prev_ssr_id))

        # Get surrogate_id
        try:
            surrogate_id_from_ssr = ssr_payload_dict['surrogate_id']
        except Exception as exp:
            error_title = "Could not fetch surrogate_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got surrogate_id_from_ssr: " + str(surrogate_id_from_ssr))

        # Verify SLR IDs from path and ssr payload are matching
        try:
            compare_str_ids(id=link_id, id_to_compare=link_id_from_ssr)
        except ValueError as exp:
            error_title = "SLR IDs from path and ssr payload are not matching"
            error_detail = "SLR ID from path was {} and from ssr payload {}".format(link_id, link_id_from_ssr)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("SLR IDs from path and ssr payload are not matching")

        # Verify Surrogate IDs from slr and ssr are matching
        try:
            compare_str_ids(id=surrogate_id_from_slr, id_to_compare=surrogate_id_from_ssr)
        except ValueError as exp:
            error_title = "Surrogate IDs from Service Link Record and Service Link Status Record are not matching"
            error_detail = "Surrogate ID from Service Link Record was {} and from Service Link Status Record {}".format(surrogate_id_from_slr, surrogate_id_from_ssr)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Surrogate IDs from slr and ssr are not matching")

        # Verify Account owner's signature in Service Link Record
        try:
            slr_verified = verify_jws_signature_with_jwk(account_id=account_id, jws_json_to_verify=json.dumps(slr))
        except Exception as exp:
            error_title = "Could not verify Account owner's signature in Service Link Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info('Service Link Record verified')
            logger.info('Verification passed: ' + str(slr_verified))
            if not slr_verified:
                error_title = "Account owner's signature in Service Link Record was invalid"
                error_detail = "Service Link Record was not signed by specified Account Owner or signature has been corrupted."
                logger.error(error_title + " - " + error_detail)
                raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)

        # Sign ServiceLinkStatusRecord
        try:
            logger.info("Signing ServiceLinkStatusRecord")
            ssr_signed = sign_ssr(account_id=account_id, ssr_payload=ssr_payload_dict, endpoint=str(endpoint))
        except Exception as exp:
            error_title = "Could not sign ServiceLinkStatusRecord"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)

        # Get inited ServiceLinkRecord object from DB
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

        try:
            logger.info("Append data to ServiceLinkRecord object")
            slr_inited.service_link_record = slr
            slr_inited.operator_id = operator_id
            slr_inited.service_id = service_id
            slr_inited.surrogate_id = surrogate_id_from_slr
        except Exception as exp:
            error_title = "Could not append data to ServiceLinkRecord object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "ServiceLinkRecord object: " + slr_inited.log_entry)
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("Appended data to ServiceLinkRecord object")
            logger.debug("ServiceLinkRecord object: " + slr_inited.log_entry)

        # Create ServiceLinkStatusRecord object
        try:
            logger.info("Creating ServiceLinkStatusRecord object")
            ssr_entry = ServiceLinkStatusRecord(
                service_link_status_record_id=ssr_id,
                status=ssr_status,
                service_link_status_record=ssr_signed,
                service_link_record_id=link_id,
                issued_at=ssr_iat,
                prev_record_id=prev_ssr_id,
                accounts_id=account_id
            )
        except Exception as exp:
            error_title = "Could not create Service Link Status Record object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("Created ServiceLinkStatusRecord object")
            logger.debug("ServiceLinkStatusRecord object: " + ssr_entry.log_entry)

        # Store Service Link Record and Service Link Status Record
        try:
            logger.info("Storing Service Link Record and Service Link Status Record")
            stored_slr_entry, stored_ssr_entry = store_slr_and_ssr(slr_entry=slr_inited, ssr_entry=ssr_entry, endpoint=str(endpoint))
        except IntegrityError as exp:
            error_title = "Could not store Service Link Record and Service Link Status Record"
            error_detail = "Record with provided ID already exists"
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=409, title=error_title, detail=str(exp.message), source=endpoint)
        except Exception as exp:
            error_title = "Could not store Service Link Record and Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("Stored Service Link Record and Service Link Status Record")
            logger.debug("stored_slr_entry: " + stored_slr_entry.log_entry)
            logger.debug("stored_ssr_entry: " + stored_ssr_entry.log_entry)

        # Response data container
        try:
            response_data = {
              "code": code,
              "data": {
                "slr": stored_slr_entry.to_api_dict,
                "ssr": stored_ssr_entry.to_api_dict
              }
            }
        except Exception as exp:
            error_title = "Could not prepare response data"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class ApiServiceLinkRecords(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id):
        """
        Fetch list of Service Link Records

        :param account_id:
        :return: JSON array
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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

        # Get ServiceLinkRecords
        try:
            logger.info("Fetching ServiceLinkRecords")
            db_entries = get_slrs(account_id=account_id)
        except IndexError as exp:
            error_title = "No ServiceLinkRecords found"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No ServiceLinkRecords found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("ServiceLinkRecords Fetched")

        # Response data container
        try:
            db_entry_list = db_entries
            response_data = {}
            response_data['data'] = db_entry_list
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiServiceLinkStatusRecords(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id):
        """
        Fetch list of Service Link Status Records

        :param account_id:
        :param link_id:
        :return: JSON array
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("link_id: " + link_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkStatusRecords
        try:
            logger.info("Fetching ServiceLinkStatusRecords")
            db_entries = get_slsrs(account_id=account_id, slr_id=link_id)
        except IndexError as exp:
            error_title = "No ServiceLinkStatusRecords found"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except StandardError as exp:
            error_title = "ServiceLinkStatusRecords not accessible"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=403, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No ServiceLinkStatusRecords found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("ServiceLinkStatusRecords Fetched")

        # Response data container
        try:
            db_entry_list = db_entries
            response_data = {}
            response_data['data'] = db_entry_list
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)

    @requires_api_auth_user
    @requires_api_auth_sdk
    def post(self, account_id, link_id):
        """
        Constructs Service Link Status Record based on provided Service Link Status Record payload.
        Signs constructed Service Link Status Record with Account owner’s key.
        Finally Service Link Status Record is stored.

        :param account_id:
        :param link_id:
        :return: JSON object
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("link_id: " + link_id)

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
        validate_json(json_data, schema_sls_to_sign_by_account)

        # Get elements from payload
        try:
            logger.info("Get elements from payload")
            ssr_payload_dict = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not get data from request payload"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("ssr_payload from payload: " + json.dumps(ssr_payload_dict))

        # Get ssr_id
        try:
            ssr_id = ssr_payload_dict['record_id']
        except Exception as exp:
            error_title = "Could not fetch record_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got ssr_id: " + str(ssr_id))

        # Get ssr_status
        try:
            ssr_status = ssr_payload_dict['sl_status']
        except Exception as exp:
            error_title = "Could not fetch sl_status from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got ssr_status: " + str(ssr_status))

        # Get slr_id_from_ssr
        try:
            link_id_from_ssr = ssr_payload_dict['slr_id']
        except Exception as exp:
            error_title = "Could not fetch link_id_from_ssr from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got link_id_from_ssr: " + str(link_id_from_ssr))

        # Get prev_ssr_id
        try:
            prev_ssr_id = ssr_payload_dict['prev_record_id']
        except Exception as exp:
            error_title = "Could not fetch prev_ssr_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got prev_ssr_id: " + str(prev_ssr_id))

        # Get iat
        try:
            ssr_iat = int(ssr_payload_dict['iat'])
        except Exception as exp:
            error_title = "Could not fetch iat from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got iat: " + str(prev_ssr_id))

        # Get surrogate_id
        try:
            surrogate_id_from_ssr = ssr_payload_dict['surrogate_id']
        except Exception as exp:
            error_title = "Could not fetch surrogate_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got surrogate_id_from_ssr: " + str(surrogate_id_from_ssr))

        # Verify SLR IDs from path and ssr payload are matching
        try:
            compare_str_ids(id=link_id, id_to_compare=link_id_from_ssr)
        except ValueError as exp:
            error_title = "SLR IDs from path and ssr payload are not matching"
            error_detail = "SLR ID from path was {} and from ssr payload {}".format(link_id, link_id_from_ssr)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("SLR IDs from path and ssr payload are not matching")

        # Sign ServiceLinkStatusRecord
        try:
            logger.info("Signing ServiceLinkStatusRecord")
            ssr_signed = sign_ssr(account_id=account_id, ssr_payload=ssr_payload_dict, endpoint=str(endpoint))
        except Exception as exp:
            error_title = "Could not sign ServiceLinkStatusRecord"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)

        # Get inited ServiceLinkRecord object from DB
        try:
            logger.info("Get inited ServiceLinkRecord object")
            slr_entry = get_slr_record(account_id=account_id, slr_id=link_id, endpoint=endpoint)
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
            logger.info("Got ServiceLinkRecord object")
            logger.debug("slr_entry: " + slr_entry.log_entry)

        # Create ServiceLinkStatusRecord object
        try:
            logger.info("Creating ServiceLinkStatusRecord object")
            ssr_entry = ServiceLinkStatusRecord(
                service_link_status_record_id=ssr_id,
                status=ssr_status,
                service_link_status_record=ssr_signed,
                service_link_record_id=link_id,
                service_link_records_id=slr_entry.id,
                issued_at=ssr_iat,
                prev_record_id=prev_ssr_id,
                accounts_id=account_id
            )
        except Exception as exp:
            error_title = "Could not create Service Link Status Record object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("Created ServiceLinkStatusRecord object")
            logger.debug("ServiceLinkStatusRecord object: " + ssr_entry.log_entry)

        # Store Service Link Status Record
        try:
            logger.info("Storing Service Link Status Record")
            stored_ssr_entry = store_ssr(ssr_entry=ssr_entry, endpoint=str(endpoint))
        except IntegrityError as exp:
            error_title = "Could not store Service Link Status Record"
            error_detail = "Record with provided ID already exists"
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=409, title=error_title, detail=str(exp.message), source=endpoint)
        except Exception as exp:
            error_title = "Could not store Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("Stored Service Link Status Record")
            logger.debug("stored_ssr_entry: " + stored_ssr_entry.log_entry)

        # Response data container
        try:
            response_data = {
              "data": stored_ssr_entry.to_api_dict
            }
        except Exception as exp:
            error_title = "Could not prepare response data"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class ApiServiceLinkStatusRecordsSigned(Resource):
    @requires_api_auth_sdk
    def post(self, account_id, link_id):
        """
        Stores Service Link Status Record signed by Operator.

        :param account_id:
        :param link_id:
        :return: JSON object
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("link_id: " + link_id)

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
        validate_json(json_data, schema_sls_signed_by_operator)

        # Get Service Link Status Record from payload
        try:
            logger.info("Get Service Link Status Record from payload")
            ssr_dict = json_data['data']['ssr']['attributes']
        except Exception as exp:
            error_title = "Could not get data from request payload"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("ssr_dict from payload: " + json.dumps(ssr_dict))

        try:
            logger.info("Get Service Link Status Record ID from payload")
            ssr_id_from_record_payload = str(json_data['data']['ssr']['id'])
        except Exception as exp:
            error_title = "Could not get data from request payload"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("ssr_id_from_record_payload: " + ssr_id_from_record_payload)

        #
        # Get Service Link Status payload
        try:
            logger.info("Get Service Link Status payload")
            ssr_payload_dict = json_data['data']['ssr_payload']['attributes']
        except Exception as exp:
            error_title = "Could not get data from request payload"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("ssr_payload from payload: " + json.dumps(ssr_payload_dict))

        # Get ssr_id
        try:
            ssr_id = ssr_payload_dict['record_id']
        except Exception as exp:
            error_title = "Could not fetch record_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got ssr_id: " + str(ssr_id))

        # Get ssr_status
        try:
            ssr_status = ssr_payload_dict['sl_status']
        except Exception as exp:
            error_title = "Could not fetch sl_status from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got ssr_status: " + str(ssr_status))

        # Get slr_id_from_ssr
        try:
            link_id_from_ssr = ssr_payload_dict['slr_id']
        except Exception as exp:
            error_title = "Could not fetch link_id_from_ssr from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got link_id_from_ssr: " + str(link_id_from_ssr))

        # Get prev_ssr_id
        try:
            prev_ssr_id = ssr_payload_dict['prev_record_id']
        except Exception as exp:
            error_title = "Could not fetch prev_ssr_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got prev_ssr_id: " + str(prev_ssr_id))

        # Get iat
        try:
            ssr_iat = int(ssr_payload_dict['iat'])
        except Exception as exp:
            error_title = "Could not fetch iat from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got iat: " + str(prev_ssr_id))

        # Get surrogate_id
        try:
            surrogate_id_from_ssr = ssr_payload_dict['surrogate_id']
        except Exception as exp:
            error_title = "Could not fetch surrogate_id from Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.debug("Got surrogate_id_from_ssr: " + str(surrogate_id_from_ssr))

        # Verify SLR IDs from path and ssr payload are matching
        try:
            compare_str_ids(id=link_id, id_to_compare=link_id_from_ssr)
        except ValueError as exp:
            error_title = "SLR IDs from path and ssr payload are not matching"
            error_detail = "SLR ID from path was {} and from ssr payload {}".format(link_id, link_id_from_ssr)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("SLR IDs from path and ssr payload are not matching")

        # Verify SSR IDs from record and ssr payload are matching
        try:
            compare_str_ids(id=ssr_id_from_record_payload, id_to_compare=ssr_id)
        except ValueError as exp:
            error_title = "SSR IDs from record and ssr payload are not matching"
            error_detail = "SSR ID from record was {} and from ssr payload {}".format(ssr_id_from_record_payload, ssr_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("SLR IDs from record and ssr payload are not matching")

        # Get inited ServiceLinkRecord object from DB
        try:
            logger.info("Get inited ServiceLinkRecord object")
            slr_entry = get_slr_record(account_id=account_id, slr_id=link_id, endpoint=endpoint)
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
            logger.info("Got ServiceLinkRecord object")
            logger.debug("slr_entry: " + slr_entry.log_entry)

        # Create ServiceLinkStatusRecord object
        try:
            logger.info("Creating ServiceLinkStatusRecord object")
            ssr_entry = ServiceLinkStatusRecord(
                service_link_status_record_id=ssr_id,
                status=ssr_status,
                service_link_status_record=ssr_dict,
                service_link_record_id=link_id,
                service_link_records_id=slr_entry.id,
                issued_at=ssr_iat,
                prev_record_id=prev_ssr_id,
                accounts_id=account_id
            )
        except Exception as exp:
            error_title = "Could not create Service Link Status Record object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("Created ServiceLinkStatusRecord object")
            logger.debug("ServiceLinkStatusRecord object: " + ssr_entry.log_entry)

        # Store Service Link Status Record
        try:
            logger.info("Storing Service Link Status Record")
            stored_ssr_entry = store_ssr(ssr_entry=ssr_entry, endpoint=str(endpoint))
        except IntegrityError as exp:
            error_title = "Could not store Service Link Status Record"
            error_detail = "Record with provided ID already exists"
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=409, title=error_title, detail=str(exp.message), source=endpoint)
        except Exception as exp:
            error_title = "Could not store Service Link Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("Stored Service Link Status Record")
            logger.debug("stored_ssr_entry: " + stored_ssr_entry.log_entry)

        # Response data container
        try:
            response_data = {
              "data": stored_ssr_entry.to_api_dict
            }
        except Exception as exp:
            error_title = "Could not prepare response data"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail + ": " + "Exception: " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class ApiServiceLinkStatusRecord(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id, status_id):
        """
        Fetch Service Link Status Record by ID

        :param account_id:
        :param link_id:
        :param status_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id, status_id=status_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("link_id: " + link_id)

        try:
            status_id = str(status_id)
        except Exception as exp:
            error_title = "Unsupported status_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("status_id: " + status_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkStatusRecord
        try:
            logger.info("Fetching ServiceLinkStatusRecord")
            db_entries = get_slsr(account_id=account_id, slr_id=link_id, slsr_id=status_id)
        except IndexError as exp:
            error_title = "Service Link Status Record not found with provided information"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except StandardError as exp:
            error_title = "ServiceLinkStatusRecord not accessible"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=403, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No ServiceLinkStatusRecord found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("ServiceLinkStatusRecord Fetched")

        # Response data container
        try:
            response_data = {}
            response_data['data'] = db_entries
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiLastServiceLinkStatusRecord(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id):
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

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

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("link_id: " + link_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get last Service Link Status Record
        try:
            last_slsr_dict = get_last_slr_status(account_id=account_id, slr_id=link_id, endpoint=endpoint)
        except Exception as exp:
            error_title = "Failed to get last Service Link Status Record of Service Link"
            logger.error(error_title + ": " + repr(exp))
            raise
        else:
            logger.debug("Service Link Status Record: " + json.dumps(last_slsr_dict))

        # Response data container
        try:
            response_data = {}
            response_data['data'] = last_slsr_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + json.dumps(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiServiceLinkRecordsForService(Resource):
    @requires_api_auth_sdk
    def get(self, service_id):
        """
        Fetch list of Service Link Records related to Service

        :param account_id:
        :return: JSON array
        """
        try:
            endpoint = str(api.url_for(self, service_id=service_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        try:
            service_id = str(service_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported service_id", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Service ID from path: " + service_id)

        try:
            surrogate_id = request.args.get('surrogate_id', None)
            if surrogate_id is not None:
                surrogate_id = str(surrogate_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported surrogate_id", detail=repr(exp), source=endpoint)
        else:
            if surrogate_id is not None:
                logger.info("Surrogate ID from query params: " + surrogate_id)
            else:
                logger.info("No Surrogate ID in query params")

        # Get ServiceLinkRecords
        try:
            logger.info("Fetching ServiceLinkRecords")
            if surrogate_id is None:
                db_entries = get_slrs_for_service(service_id=service_id)
            else:
                db_entries = get_slrs_for_service(service_id=service_id, surrogate_id=surrogate_id)
        except IndexError as exp:
            error_title = "Service Link Record not found with provided information"
            error_detail = "Service ID was {} and Surrogate ID was {}".format(service_id, surrogate_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No ServiceLinkRecords found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("ServiceLinkRecords Fetched")

        # Response data container
        try:
            db_entry_list = db_entries
            response_data = {}
            response_data['data'] = db_entry_list
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiServiceLinkRecordForService(Resource):
    @requires_api_auth_sdk
    def get(self, service_id, link_id):
        """
        Fetch Service Link Record by Service ID and Service Link ID

        :param service_id:
        :param link_id:
        :return: JSON Object
        """
        try:
            endpoint = str(api.url_for(self, service_id=service_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        try:
            service_id = str(service_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported service_id", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Service ID from path: " + service_id)

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("link_id: " + link_id)

        # Get ServiceLinkRecord
        try:
            logger.info("Fetching ServiceLinkRecord")
            db_entries = get_slr_for_service(service_id=service_id, slr_id=link_id)
        except IndexError as exp:
            error_title = "Service Link Record not found with provided information"
            error_detail = "Service ID was {} and Service Link Record ID was {}".format(link_id, link_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No ServiceLinkRecord found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("ServiceLinkRecord Fetched")

        # Response data container
        try:
            response_data = {}
            response_data['data'] = db_entries
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class Surrogate(Resource):
    @requires_api_auth_sdk
    def get(self, service_id, surrogate_id):
        """
        Fetch Account ID for Service Id - Surrogate ID pair

        :param service_id:
        :param surrogate_id:
        :return: JSON object
        """
        try:
            endpoint = str(api.url_for(self, service_id=service_id, surrogate_id=surrogate_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        try:
            service_id = str(service_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported service_id", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Service ID from path: " + service_id)

        try:
            surrogate_id = str(surrogate_id)
        except Exception as exp:
            error_title = "Unsupported surrogate_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Surrogate ID from path: " + surrogate_id)

        try:
            surrogate_object = get_account_id_by_service_and_surrogate_id(surrogate_id=surrogate_id, service_id=service_id, endpoint=endpoint)
        except IndexError as exp:
            raise ApiError(code=404, title="Surrogate object could not be found with provided information", detail=repr(exp), source=endpoint)
        except Exception as exp:
            logger.error('Could not get Surrogate object: ' + repr(exp))
            raise ApiError(code=500, title="Could not get SurrogateId object", detail=repr(exp), source=endpoint)
        else:
            logger.debug('Got Surrogate object: ' + surrogate_object.log_entry)

        # Response data container
        try:
            response_data = {}
            response_data['data'] = surrogate_object.to_api_dict
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
api.add_resource(ApiServiceLinkInitSource, '/accounts/<string:account_id>/servicelinks/init/source/', endpoint='slr_init_source')
api.add_resource(ApiServiceLinkInitSink, '/accounts/<string:account_id>/servicelinks/init/sink/', endpoint='slr_init_sink')
api.add_resource(ApiServiceLink, '/accounts/<string:account_id>/servicelinks/<string:link_id>/', endpoint='slr')
api.add_resource(ApiServiceLinkStore, '/accounts/<string:account_id>/servicelinks/<string:link_id>/store/', endpoint='slr_store')
api.add_resource(ApiServiceLinkRecords, '/accounts/<string:account_id>/servicelinks/', endpoint='slr_listing')
api.add_resource(ApiServiceLinkStatusRecords, '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses/', endpoint='slr_status_listing')
api.add_resource(ApiServiceLinkStatusRecordsSigned, '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses/signed/', endpoint='slr_status_signed')
api.add_resource(ApiServiceLinkStatusRecord, '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses/<string:status_id>/', endpoint='slr_status')
api.add_resource(ApiLastServiceLinkStatusRecord, '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses/last/', endpoint='slr_status_last')
api.add_resource(ApiServiceLinkRecordsForService, '/services/<string:service_id>/servicelinks/', endpoint='slr_listing_for_service')
api.add_resource(ApiServiceLinkRecordForService, '/services/<string:service_id>/servicelinks/<string:link_id>/', endpoint='slr_for_service')
api.add_resource(Surrogate, '/services/<string:service_id>/surrogates/<string:surrogate_id>/', endpoint='surrogate')


