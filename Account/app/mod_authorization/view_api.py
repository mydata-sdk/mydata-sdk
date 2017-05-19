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
from app.mod_authorization.schemas import schema_consent_new, schema_consent_status_new, \
    schema_consent_status_signed_new
from app.mod_blackbox.controllers import sign_jws_with_jwk, generate_and_sign_jws, get_account_public_key, \
    verify_jws_signature_with_jwk
from app.mod_database.helpers import get_db_cursor
from app.mod_database.models import ServiceLinkRecord, ServiceLinkStatusRecord, ConsentRecord, ConsentStatusRecord
from app.mod_authorization.controllers import sign_cr, sign_csr, store_cr_and_csr, get_auth_token_data, \
    get_last_cr_status, store_csr, get_csrs, get_crs, get_cr, get_last_cr, get_csr

mod_authorization_api = Blueprint('authorization_api', __name__, template_folder='templates')
api = Api(mod_authorization_api)

# create logger with 'spam_application'
logger = get_custom_logger(__name__)


# Resources
class ApiAccountConsent(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def post(self, account_id, source_link_id, sink_link_id):
        """
        Constructs Consent Record’s and Consent Status Record’s based on provided payloads for Source and Sink services.
        Signs constructed record’s with Account owner’s key.
        After signing records are stored.

        :param account_id:
        :param source_link_id:
        :param sink_link_id:
        :return: JSON object
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, source_link_id=source_link_id, sink_link_id=sink_link_id))
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
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            source_link_id = str(source_link_id)
        except Exception as exp:
            error_title = "Unsupported source_link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("source_link_id: " + source_link_id)

        try:
            sink_link_id = str(sink_link_id)
        except Exception as exp:
            error_title = "Unsupported sink_link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("sink_link_id: " + sink_link_id)

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
        validate_json(json_data, schema_consent_new)

        # Get elements from payload
        #  Source
        try:
            # Consent Record
            source_consent_payload = json_data['data']['source']['consent_record_payload']['attributes']
            source_consent_cr_id = str(source_consent_payload['common_part']['cr_id'])
            source_consent_surrogate_id = str(source_consent_payload['common_part']['surrogate_id'])
            source_consent_slr_id = str(source_consent_payload['common_part']['slr_id'])
            source_consent_subject_id = str(source_consent_payload['common_part']['subject_id'])
            source_consent_role = str(source_consent_payload['common_part']['role'])
            source_consent_rs_id = str(source_consent_payload['common_part']['rs_description']['resource_set']['rs_id'])
        except Exception as exp:
            error_title = "Could not Consent Record data of Source Service"
            error_detail = str(exp.__class__.__name__) + " - " + str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.debug("source_consent_cr_id from payload: " + source_consent_cr_id)
            logger.debug("source_consent_surrogate_id from payload: " + source_consent_surrogate_id)
            logger.debug("source_consent_slr_id from payload: " + source_consent_slr_id)
            logger.debug("source_consent_subject_id from payload: " + source_consent_subject_id)
            logger.debug("source_consent_role from payload: " + source_consent_role)
            logger.debug("source_consent_rs_id from payload: " + source_consent_rs_id)

        try:
            # Consent Status Record
            source_status_payload = json_data['data']['source']['consent_status_record_payload']['attributes']
            source_status_record_id = str(source_status_payload['record_id'])
            source_status_surrogate_id = str(source_status_payload['surrogate_id'])
            source_status_cr_id = str(source_status_payload['cr_id'])
            source_status_consent_status = str(source_status_payload['consent_status'])
            source_status_iat = int(source_status_payload['iat'])
            source_status_prev_record_id = str(source_status_payload['prev_record_id'])
        except Exception as exp:
            error_title = "Could not Consent Status Record data of Source Service"
            error_detail = str(exp.__class__.__name__) + " - " + str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.debug("source_status_record_id from payload: " + source_status_record_id)
            logger.debug("source_status_surrogate_id from payload: " + source_status_surrogate_id)
            logger.debug("source_status_cr_id from payload: " + source_status_cr_id)
            logger.debug("source_status_consent_status from payload: " + source_status_consent_status)
            logger.debug("source_status_iat from payload: " + str(source_status_iat))
            logger.debug("source_status_prev_record_id from payload: " + source_status_prev_record_id)

        try:
            logger.info("Verify that Source SLR IDs from path and payload are matching")
            compare_str_ids(id=source_link_id, id_to_compare=source_consent_slr_id)
        except ValueError as exp:
            error_title = "Source Service SLR IDs from path and Consent Record payload are not matching"
            error_detail = "SLR ID from path was {} and from payload {}".format(source_link_id, source_consent_slr_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Source Service SLR IDs from path and payload are matching")

        try:
            logger.info("Verify that Source Consent IDs from payload are matching")
            compare_str_ids(id=source_consent_cr_id, id_to_compare=source_status_cr_id)
        except ValueError as exp:
            error_title = "Source Service Consent IDs from Consent Record payload and Consent Status Record payload are not matching"
            error_detail = "Consent ID from Consent Record payload was {} and from Consent Status Record payload {}".format(source_consent_cr_id, source_status_cr_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Source Service Consent IDs from payload are matching")

        try:
            logger.info("Verify that Source Surrogate IDs from payload are matching")
            compare_str_ids(id=source_consent_surrogate_id, id_to_compare=source_status_surrogate_id)
        except ValueError as exp:
            error_title = "Source Service Surrogate IDs from Consent Record payload and Consent Status Record payload are not matching"
            error_detail = "Surrogate ID from Consent payload was {} and from Consent Status payload {}".format(source_consent_surrogate_id, source_status_surrogate_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Source Service Surrogate IDs from payload are matching")

        #  Sink
        try:
            # Consent Record
            sink_consent_payload = json_data['data']['sink']['consent_record_payload']['attributes']
            sink_consent_cr_id = str(sink_consent_payload['common_part']['cr_id'])
            sink_consent_surrogate_id = str(sink_consent_payload['common_part']['surrogate_id'])
            sink_consent_slr_id = str(sink_consent_payload['common_part']['slr_id'])
            sink_consent_subject_id = str(sink_consent_payload['common_part']['subject_id'])
            sink_consent_role = str(sink_consent_payload['common_part']['role'])
            sink_consent_rs_id = str(sink_consent_payload['common_part']['rs_description']['resource_set']['rs_id'])
        except Exception as exp:
            error_title = "Could not get Consent Record data of Sink Service"
            error_detail = str(exp.__class__.__name__) + " - " + str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.debug("sink_consent_cr_id from payload: " + sink_consent_cr_id)
            logger.debug("sink_consent_surrogate_id from payload: " + sink_consent_surrogate_id)
            logger.debug("sink_consent_slr_id from payload: " + sink_consent_slr_id)
            logger.debug("sink_consent_subject_id from payload: " + sink_consent_subject_id)
            logger.debug("sink_consent_role from payload: " + sink_consent_role)
            logger.debug("sink_consent_rs_id from payload: " + sink_consent_rs_id)

        try:
            # Consent Status Record
            sink_status_payload = json_data['data']['sink']['consent_status_record_payload']['attributes']
            sink_status_record_id = str(sink_status_payload['record_id'])
            sink_status_surrogate_id = str(sink_status_payload['surrogate_id'])
            sink_status_cr_id = str(sink_status_payload['cr_id'])
            sink_status_consent_status = str(sink_status_payload['consent_status'])
            sink_status_iat = int(sink_status_payload['iat'])
            sink_status_prev_record_id = str(sink_status_payload['prev_record_id'])
        except Exception as exp:
            error_title = "Could not get Consent Status Record data of Sink Service"
            error_detail = str(exp.__class__.__name__) + " - " + str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.debug("sink_status_record_id from payload: " + sink_status_record_id)
            logger.debug("sink_status_surrogate_id from payload: " + sink_status_surrogate_id)
            logger.debug("sink_status_cr_id from payload: " + sink_status_cr_id)
            logger.debug("sink_status_consent_status from payload: " + sink_status_consent_status)
            logger.debug("sink_status_iat from payload: " + str(sink_status_iat))
            logger.debug("sink_status_prev_record_id from payload: " + sink_status_prev_record_id)

        try:
            logger.info("Verify that Sink Service SLR IDs from path and payload are matching")
            compare_str_ids(id=sink_link_id, id_to_compare=sink_consent_slr_id)
        except ValueError as exp:
            error_title = "Sink Service SLR IDs from path and Consent Record payload are not matching"
            error_detail = "SLR ID from path was {} and from payload {}".format(sink_link_id, sink_consent_slr_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Sink Service SLR IDs from path and payload are matching")

        try:
            logger.info("Verify that Sink Consent IDs from payload are matching")
            compare_str_ids(id=sink_consent_cr_id, id_to_compare=sink_status_cr_id)
        except ValueError as exp:
            error_title = "Sink Service Consent IDs from Consent Record payload and Consent Status Record payload are not matching"
            error_detail = "Consent ID from Consent payload was {} and from Consent Status payload {}".format(sink_consent_cr_id, sink_status_cr_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Sink Service Consent IDs from payload are matching")

        try:
            logger.info("Verify that Sink Surrogate IDs from payload are matching")
            compare_str_ids(id=sink_consent_surrogate_id, id_to_compare=sink_status_surrogate_id)
        except ValueError as exp:
            error_title = "Sink Service Surrogate IDs from Consent Record payload and Consent Status Record payload are not matching"
            error_detail = "Surrogate ID from Consent payload was {} and from Consent Status payload {}".format(sink_consent_surrogate_id, sink_status_surrogate_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Sink Service Surrogate IDs from payload are matching")

        ######
        # Sign Consent Records and Consent Status Records
        ####
        try:
            logger.info("Signing Consent Record of Source Service")
            source_cr_signed = sign_cr(account_id=account_id, payload=source_consent_payload, endpoint=endpoint)
        except Exception as exp:
            error_title = "Could not sign Consent Record of Source Service"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record of Source Service signed")
            logger.debug("Consent Record of Source Service: " + json.dumps(source_cr_signed))

        try:
            logger.info("Signing Consent Status Record of Source Service")
            source_csr_signed = sign_csr(account_id=account_id, payload=source_status_payload, endpoint=endpoint)
        except Exception as exp:
            error_title = "Could not sign Consent Status Record of Source Service"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Status Record of Source Service signed")
            logger.debug("Consent Status Record of Source Service: " + json.dumps(source_csr_signed))

        try:
            logger.info("Signing Consent Record of Sink Service")
            sink_cr_signed = sign_cr(account_id=account_id, payload=sink_consent_payload, endpoint=endpoint)
        except Exception as exp:
            error_title = "Could not sign Consent Record of Sink Service"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record of Sink Service")
            logger.debug("Consent Record of Sink Service: " + json.dumps(sink_cr_signed))

        try:
            logger.info("Signing Consent Status Record of Sink Service")
            sink_csr_signed = sign_csr(account_id=account_id, payload=sink_status_payload, endpoint=endpoint)
        except Exception as exp:
            error_title = "Could not sign Consent Status Record of Sink Service"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Sink's Consent Status Record of Sink Service")
            logger.debug("Consent Status Record of Sink Service: " + json.dumps(sink_csr_signed))

        #########
        # Store #
        #########

        logger.info("Creating objects to store")
        # Service Link Record of Source Service
        try:
            logger.info("Creating Service Link Record of Source Service")
            source_slr_entry = ServiceLinkRecord(
                surrogate_id=source_consent_surrogate_id,
                account_id=account_id,
                service_link_record_id=source_consent_slr_id
            )
        except Exception as exp:
            error_title = "Failed to create Source's Service Link Record object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Source's Service Link Record object created")
            logger.info("Source's Service Link Record object: " + source_slr_entry.log_entry)

        # Service Link Record of Sink Service
        try:
            logger.info("Creating Source's Service Link Record object")
            sink_slr_entry = ServiceLinkRecord(
                surrogate_id=sink_consent_surrogate_id,
                account_id=account_id,
                service_link_record_id=sink_consent_slr_id
            )
        except Exception as exp:
            error_title = "Failed to create Sink's Service Link Record object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Source's Service Link Record object created")
            logger.info("Source's Service Link Record object: " + sink_slr_entry.log_entry)

        # Consent Record of Source Service
        try:
            logger.info("Creating Consent Record of Source Service")
            source_cr_entry = ConsentRecord(
                consent_record=source_cr_signed,
                consent_id=source_consent_cr_id,
                surrogate_id=source_consent_surrogate_id,
                resource_set_id=source_consent_rs_id,
                service_link_record_id=source_consent_slr_id,
                subject_id=source_consent_subject_id,
                role=source_consent_role,
                consent_pair_id=sink_consent_cr_id,
                accounts_id=account_id
            )
        except Exception as exp:
            error_title = "Failed to create Source's Consent Record object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record of Source Service created")
            logger.info("Consent Record of Source Service: " + source_cr_entry.log_entry)

        # Consent Record of Sink Service
        try:
            logger.info("Creating Consent Record of Sink Service")
            sink_cr_entry = ConsentRecord(
                consent_record=sink_cr_signed,
                consent_id=sink_consent_cr_id,
                surrogate_id=sink_consent_surrogate_id,
                resource_set_id=sink_consent_rs_id,
                service_link_record_id=sink_consent_slr_id,
                subject_id=sink_consent_subject_id,
                role=sink_consent_role,
                consent_pair_id=source_consent_cr_id,
                accounts_id=account_id
            )
        except Exception as exp:
            error_title = "Failed to create Sink's Consent Record object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record of Sink Service created")
            logger.info("Consent Record of Sink Service: " + sink_cr_entry.log_entry)

        # Consent Status Record of Source Service
        try:
            logger.info("Creating Consent Status Record of Source Service")
            source_csr_entry = ConsentStatusRecord(
                consent_status_record_id=source_status_record_id,
                status=sink_status_consent_status,
                consent_status_record=source_csr_signed,
                consent_record_id=source_status_cr_id,
                issued_at=source_status_iat,
                prev_record_id=source_status_prev_record_id,
                accounts_id=account_id
            )
        except Exception as exp:
            error_title = "Failed to create Source's Consent Status Record object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Status Record of Source Service created")
            logger.info("Consent Status Record of Source Service: " + source_csr_entry.log_entry)

        # Consent Status Record of Sink Service
        try:
            logger.info("Creating Consent Status Record of Sink Service")
            sink_csr_entry = ConsentStatusRecord(
                consent_status_record_id=sink_status_record_id,
                status=sink_status_consent_status,
                consent_status_record=sink_csr_signed,
                consent_record_id=sink_status_cr_id,
                issued_at=sink_status_iat,
                prev_record_id=sink_status_prev_record_id,
                accounts_id=account_id
            )
        except Exception as exp:
            error_title = "Failed to create Sink's Consent Status Record object"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Status Record of Sink Service created")
            logger.info("Consent Status Record of Sink Service: " + sink_csr_entry.log_entry)

        # Store Consent Records and Consent Status Records
        try:
            logger.info("About to store Consent Records and Consent Status Records")
            stored_source_cr_entry, stored_source_csr_entry, stored_sink_cr_entry, stored_sink_csr_entry = \
                store_cr_and_csr(
                    source_slr_entry=source_slr_entry,
                    sink_slr_entry=sink_slr_entry,
                    source_cr_entry=source_cr_entry,
                    source_csr_entry=source_csr_entry,
                    sink_cr_entry=sink_cr_entry,
                    sink_csr_entry=sink_csr_entry,
                    endpoint=endpoint
                )
        except IndexError as exp:
            error_title = "Could not store Consent Records and Consent Status Records"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        except KeyError as exp:
            error_title = "Could not store Consent Records and Consent Status Records"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        except RuntimeError as exp:
            error_title = "Could not store Consent Records and Consent Status Records"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "Could not store Consent Records and Consent Status Records"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Stored Consent Record and Consent Status Record")
            logger.info("Source CR: " + stored_source_cr_entry.log_entry)
            logger.info("Source CSR: " + stored_source_csr_entry.log_entry)
            logger.info("Sink CR: " + stored_sink_cr_entry.log_entry)
            logger.info("Sink CSR: " + stored_sink_csr_entry.log_entry)

        # Response data container
        try:
            response_data = {}
            response_data['data'] = {}

            response_data['data']['source'] = {}
            response_data['data']['source']['consent_record'] = stored_source_cr_entry.to_api_dict
            response_data['data']['source']['consent_status_record'] = stored_source_csr_entry.to_api_dict

            response_data['data']['sink'] = {}
            response_data['data']['sink']['consent_record'] = stored_sink_cr_entry.to_api_dict
            response_data['data']['sink']['consent_status_record'] = stored_sink_csr_entry.to_api_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + json.dumps(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class AuthorizationTokenData(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, sink_cr_id):

        try:
            endpoint = str(api.url_for(self, sink_cr_id=sink_cr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            api_key = request.headers.get('Api-Key')
        except Exception as exp:
            logger.error("No ApiKey in headers")
            logger.debug("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)

        try:
            sink_cr_id = str(sink_cr_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported sink_cr_id", detail=repr(exp), source=endpoint)
        else:
            logger.debug("sink_cr_id: " + repr(sink_cr_id))

        # Init Sink's Consent Record Object
        try:
            sink_cr_entry = ConsentRecord(consent_id=sink_cr_id, role="Sink")
        except Exception as exp:
            error_title = "Failed to create Sink's Consent Record object"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("sink_cr_entry: " + sink_cr_entry.log_entry)

        try:
            source_cr, sink_slr = get_auth_token_data(sink_cr_object=sink_cr_entry)
        except Exception as exp:
            error_title = "Failed to get Authorization token data"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("source_cr: " + source_cr.log_entry)
            logger.debug("sink_slr: " + sink_slr.log_entry)


        # Response data container
        try:
            response_data = {}
            response_data['data'] = {}

            response_data['data']['source'] = {}
            response_data['data']['source']['consentRecord'] = {}
            response_data['data']['source']['consentRecord']['type'] = "ConsentRecord"
            response_data['data']['source']['consentRecord']['attributes'] = {}
            response_data['data']['source']['consentRecord']['attributes']['cr'] = source_cr.to_record_dict

            response_data['data']['sink'] = {}
            response_data['data']['sink']['serviceLinkRecord'] = {}
            response_data['data']['sink']['serviceLinkRecord']['type'] = "ServiceLinkRecord"
            response_data['data']['sink']['serviceLinkRecord']['attributes'] = {}
            response_data['data']['sink']['serviceLinkRecord']['attributes']['slr'] = sink_slr.to_record_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + json.dumps(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiAccountConsentStatus(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def post(self, account_id, consent_id):
        try:
            endpoint = str(api.url_for(self, account_id=account_id, consent_id=consent_id))
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
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("consent_id: " + consent_id)

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
        validate_json(json_data, schema_consent_status_new)

        # Get elements from payload
        try:
            # Consent Status Record
            status_payload = json_data['data']['attributes']
            record_id = str(status_payload['record_id'])
            surrogate_id = str(status_payload['surrogate_id'])
            cr_id = str(status_payload['cr_id'])
            consent_status = str(status_payload['consent_status'])
            iat = int(status_payload['iat'])
            prev_record_id = str(status_payload['prev_record_id'])
        except Exception as exp:
            error_title = "Could not Consent Status Record data"
            error_detail = str(exp.__class__.__name__) + " - " + str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.debug("record_id from payload: " + record_id)
            logger.debug("surrogate_id from payload: " + surrogate_id)
            logger.debug("cr_id from payload: " + cr_id)
            logger.debug("consent_status from payload: " + consent_status)
            logger.debug("iat from payload: " + str(iat))
            logger.debug("prev_record_id from payload: " + prev_record_id)

        # Check IDs
        try:
            logger.info("Verify that Consent IDs from path and payload are matching")
            compare_str_ids(id=consent_id, id_to_compare=cr_id)
        except ValueError as exp:
            error_title = "Consent IDs from path and payload are not matching"
            error_detail = "Consent ID from path was {} and from payload {}".format(consent_id, cr_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent IDs from path and payload are matching")

        ######
        # Sign Consent Records and Consent Status Records
        ####
        try:
            logger.info("Signing Consent Status Record")
            csr_signed = sign_csr(account_id=account_id, payload=status_payload, endpoint=endpoint)
        except Exception as exp:
            error_title = "Could not sign Consent Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Status Record signed")
            logger.debug("Consent Status Record: " + json.dumps(csr_signed))

        #
        # Store Consent Status Record
        try:
            csr_object = store_csr(
                account_id=account_id,
                record_id=record_id,
                cr_id=consent_id,
                surrogate_id=surrogate_id,
                consent_status=consent_status,
                iat=iat,
                prev_record_id=prev_record_id,
                csr_signed=csr_signed,
                endpoint=endpoint
            )
        except IndexError as exp:
            error_title = "Could not store Consent Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        except KeyError as exp:
            error_title = "Could not store Consent Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        except RuntimeError as exp:
            error_title = "Could not store Consent Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "Could not store Consent Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.debug("Stored Consent Status Record: " + csr_object.log_entry)

        # Response data container
        try:
            response_data = {}
            response_data['data'] = csr_object.to_api_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + json.dumps(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class ApiAccountConsentStatusSigned(Resource):
    @requires_api_auth_sdk
    def post(self, account_id, consent_id):
        try:
            endpoint = str(api.url_for(self, account_id=account_id, consent_id=consent_id))
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
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("consent_id: " + consent_id)

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
        validate_json(json_data, schema_consent_status_signed_new)

        # Get elements from payload
        try:
            # Consent Status Record
            status_record_id = json_data['data']['csr']['id']
            status_record = json_data['data']['csr']['attributes']
            status_payload = json_data['data']['csr_payload']['attributes']
            record_id = str(status_payload['record_id'])
            surrogate_id = str(status_payload['surrogate_id'])
            cr_id = str(status_payload['cr_id'])
            consent_status = str(status_payload['consent_status'])
            iat = int(status_payload['iat'])
            prev_record_id = str(status_payload['prev_record_id'])
        except Exception as exp:
            error_title = "Could not Consent Status Record data"
            error_detail = str(exp.__class__.__name__) + " - " + str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.debug("status_record from payload: " + json.dumps(status_record))
            logger.debug("record_id from payload: " + record_id)
            logger.debug("surrogate_id from payload: " + surrogate_id)
            logger.debug("cr_id from payload: " + cr_id)
            logger.debug("consent_status from payload: " + consent_status)
            logger.debug("iat from payload: " + str(iat))
            logger.debug("prev_record_id from payload: " + prev_record_id)

        # Check IDs
        try:
            logger.info("Verify that Consent IDs from path and payload are matching")
            compare_str_ids(id=consent_id, id_to_compare=cr_id)
        except ValueError as exp:
            error_title = "Consent IDs from path and payload are not matching"
            error_detail = "Consent ID from path was {} and from payload {}".format(consent_id, cr_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent IDs from path and payload are matching")

        # Check IDs
        try:
            logger.info("Verify that Consent Status Record IDs in payload are matching")
            compare_str_ids(id=status_record_id, id_to_compare=record_id)
        except ValueError as exp:
            error_title = "Consent Status Record IDs in Consent Status Record and Consent Status Record payload are not matching"
            error_detail = "Consent Status Record ID from Consent Status Record was {} and from Consent Status Record payload {}".format(status_record_id, record_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Status Record IDs in Consent Status Record and Consent Status Record payload are matching")

        #
        # Store Consent Status Record
        try:
            csr_object = store_csr(
                account_id=account_id,
                record_id=record_id,
                cr_id=consent_id,
                surrogate_id=surrogate_id,
                consent_status=consent_status,
                iat=iat,
                prev_record_id=prev_record_id,
                csr_signed=status_record,
                endpoint=endpoint
            )
        except IndexError as exp:
            error_title = "Could not store Consent Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        except KeyError as exp:
            error_title = "Could not store Consent Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        except RuntimeError as exp:
            error_title = "Could not store Consent Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "Could not store Consent Status Record"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.debug("Stored Consent Status Record: " + csr_object.log_entry)

        # Response data container
        try:
            response_data = {}
            response_data['data'] = csr_object.to_api_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + json.dumps(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class ApiConsentsForServiceLinkRecord(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id):
        """
        List Consent Records related to Service Link Record

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

        # Check path variables
        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Check query variables
        try:
            get_consent_pair = request.args.get('get_consent_pair', False)
            get_consent_pair = str(get_consent_pair)
            if get_consent_pair == "True":
                get_consent_pair = True
            else:
                get_consent_pair = False
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported get_consent_pair", detail=repr(exp), source=endpoint)
        else:
            if get_consent_pair:
                logger.info("get_consent_pair from query params: True")
            else:
                logger.info("get_consent_pair from query params: False")

        # Get ServiceLinkRecords
        try:
            logger.info("Fetching ConsentRecords")
            db_entries = get_crs(slr_id=link_id, account_id=account_id, consent_pairs=get_consent_pair)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {} and Service Link ID was {}".format(account_id, link_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No ConsentRecords found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("ConsentRecords Fetched")
            logger.debug("ConsentRecords: " + json.dumps(db_entries))

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


class ApiConsentForServiceLinkRecord(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id, consent_id):
        """
        Fetch Consent Record related to Service Link Record

        :param account_id:
        :param link_id:
        :param consent_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id, consent_id=consent_id))
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

        # Check path variables
        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Check query variables
        try:
            get_consent_pair = request.args.get('get_consent_pair', False)
            get_consent_pair = str(get_consent_pair)
            if get_consent_pair == "True":
                get_consent_pair = True
            else:
                get_consent_pair = False
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported get_consent_pair", detail=repr(exp), source=endpoint)
        else:
            if get_consent_pair:
                logger.info("get_consent_pair from query params: True")
            else:
                logger.info("get_consent_pair from query params: False")

        # Get Consent Record
        cr_array = []
        try:
            logger.info("Fetching Consent Record")
            cr_array.append(get_cr(cr_id=consent_id, slr_id=link_id, account_id=account_id))
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {}, Service Link ID was {} and Consent ID was {}.".format(account_id, link_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Get Consent Pair
        if get_consent_pair:
            try:
                logger.info("Fetching Consent Pair")
                cr_array.append(get_cr(account_id=account_id, consent_pair_id=consent_id))
            except IndexError as exp:
                error_title = "Consent Pair not found with provided information"
                error_detail = "Account ID was {}, Service Link ID was {} and Consent Pair ID was {}.".format(account_id, link_id, consent_id)
                logger.error(error_title + " - " + error_detail + ": " + repr(exp))
                raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
            except Exception as exp:
                error_title = "No Consent Pair found"
                error_detail = repr(exp)
                logger.error(error_title + " - " + error_detail)
                raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
            else:
                logger.info("Consent Pair Fetched")

        # Response data container
        try:
            response_data = {}
            response_data['data'] = cr_array
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiLastConsentForServiceLinkRecord(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id):
        """
        Fetch Last Consent Record related to Service Link Record

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

        # Check path variables
        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Check query variables
        try:
            get_consent_pair = request.args.get('get_consent_pair', False)
            get_consent_pair = str(get_consent_pair)
            if get_consent_pair == "True":
                get_consent_pair = True
            else:
                get_consent_pair = False
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported get_consent_pair", detail=repr(exp), source=endpoint)
        else:
            if get_consent_pair:
                logger.info("get_consent_pair from query params: True")
            else:
                logger.info("get_consent_pair from query params: False")

        # Get Consent Record
        try:
            logger.info("Fetching ConsentRecords")
            cr_array = get_last_cr(slr_id=link_id, account_id=account_id, consent_pairs=get_consent_pair)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {} and Service Link ID was {}".format(account_id, link_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No ConsentRecords found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("ConsentRecords Fetched")
            logger.debug("ConsentRecords: " + json.dumps(cr_array))

        # Response data container
        try:
            response_data = {}
            response_data['data'] = cr_array
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiConsentStatusesForServiceLinkRecord(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id, consent_id):
        """
        Fetch list of Consent Status Records

        :param account_id:
        :param link_id:
        :param consent_id:
        :return: JSON array
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id, consent_id=consent_id))
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
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("link_id: " + link_id)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("consent_id: " + consent_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Check query variables
        try:
            status_id = request.args.get('status_id', "")
            status_id = str(status_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported status_id", detail=repr(exp), source=endpoint)
        else:
            logger.info("status_id from query params: {}".format(status_id))

        # Get Consent Record
        try:
            logger.info("Fetching Consent Record")
            cr = get_cr(cr_id=consent_id, slr_id=link_id, account_id=account_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {}, Service Link ID was {} and Consent ID was {}.".format(account_id, link_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Get Consent Status Records
        try:
            logger.info("Fetching Consent Status Records")
            db_entries = get_csrs(account_id=account_id, consent_id=consent_id, status_id=status_id)
        except IndexError as exp:
            error_title = "Consent Status Records not found with provided information"
            error_detail = "Account ID was {} Service Link ID was {}, and Consent ID was {}. Status ID from query parameters was {}.".format(account_id, link_id, consent_id, status_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Status Records found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Status Records Fetched")

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


class ApiConsentStatusForServiceLinkRecord(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id, consent_id, status_id):
        """
        Fetch Consent Status Record

        :param account_id:
        :param link_id:
        :param consent_id:
        :param status_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id, consent_id=consent_id, status_id=status_id))
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

        # Check path variables
        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            status_id = str(status_id)
        except Exception as exp:
            error_title = "Unsupported status_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Consent Record
        try:
            logger.info("Fetching Consent Record")
            cr = get_cr(cr_id=consent_id, slr_id=link_id, account_id=account_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {}, Service Link ID was {} and Consent ID was {}.".format(account_id, link_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Get Consent Status Record
        try:
            logger.info("Fetching Consent Record")
            cr_entry = get_csr(cr_id=consent_id, account_id=account_id, csr_id=status_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {}, Service Link ID was {}, Consent ID was {} and Consent Status ID was {}.".format(account_id, link_id, consent_id, status_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Response data container
        try:
            response_data = {}
            response_data['data'] = cr_entry
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiConsentsForAccount(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id):
        """
        Fetch list of Consent Records related to Account

        :param account_id:
        :param link_id:
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

        # Check path variables
        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkRecords
        try:
            logger.info("Fetching ConsentRecords")
            db_entries = get_crs(account_id=account_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {}".format(account_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No ConsentRecords found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("ConsentRecords Fetched")
            logger.debug("ConsentRecords: " + json.dumps(db_entries))

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


class ApiConsentForAccount(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, consent_id):
        """
        Fetch Consent Record related to Service Link Record

        :param account_id:
        :param consent_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, consent_id=consent_id))
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

        # Check path variables
        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Check query variables
        try:
            get_consent_pair = request.args.get('get_consent_pair', False)
            get_consent_pair = str(get_consent_pair)
            if get_consent_pair == "True":
                get_consent_pair = True
            else:
                get_consent_pair = False
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported get_consent_pair", detail=repr(exp), source=endpoint)
        else:
            if get_consent_pair:
                logger.info("get_consent_pair from query params: True")
            else:
                logger.info("get_consent_pair from query params: False")

        # Get Consent Record
        cr_array = []
        try:
            logger.info("Fetching Consent Record")
            cr_array.append(get_cr(cr_id=consent_id, account_id=account_id))
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {} and Consent ID was {}.".format(account_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Get Consent Pair
        if get_consent_pair:
            try:
                logger.info("Fetching Consent Pair")
                cr_array.append(get_cr(account_id=account_id, consent_pair_id=consent_id))
            except IndexError as exp:
                error_title = "Consent Pair not found with provided information"
                error_detail = "Account ID was {} and Consent Pair ID was {}.".format(account_id, consent_id)
                logger.error(error_title + " - " + error_detail + ": " + repr(exp))
                raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
            except Exception as exp:
                error_title = "No Consent Pair found"
                error_detail = repr(exp)
                logger.error(error_title + " - " + error_detail)
                raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
            else:
                logger.info("Consent Pair Fetched")

        # Response data container
        try:
            response_data = {}
            response_data['data'] = cr_array
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiConsentStatusesForAccount(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, consent_id):
        """
        Fetch list of Consent Status Records

        :param account_id:
        :param consent_id:
        :return: JSON array
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, consent_id=consent_id))
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
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("consent_id: " + consent_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Check query variables
        try:
            status_id = request.args.get('status_id', "")
            status_id = str(status_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported status_id", detail=repr(exp), source=endpoint)
        else:
            logger.info("status_id from query params: {}".format(status_id))

        # Get Consent Status Records
        try:
            logger.info("Fetching Consent Status Records")
            db_entries = get_csrs(account_id=account_id, consent_id=consent_id, status_id=status_id)
        except IndexError as exp:
            error_title = "Consent Status Records not found with provided information"
            error_detail = "Account ID was {} and Consent ID was {}. Status ID from query parameters was {}.".format(account_id, consent_id, status_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Status Records found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Status Records Fetched")

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


class ApiConsentStatusForAccount(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, consent_id, status_id):
        """
        Fetch Consent Status Record

        :param account_id:
        :param consent_id:
        :param status_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, consent_id=consent_id, status_id=status_id))
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

        # Check path variables
        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            status_id = str(status_id)
        except Exception as exp:
            error_title = "Unsupported status_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Consent Status Record
        try:
            logger.info("Fetching Consent Record")
            cr_entry = get_csr(cr_id=consent_id, account_id=account_id, csr_id=status_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {}, Consent ID was {} and Consent Status ID was {}.".format(account_id, consent_id, status_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Response data container
        try:
            response_data = {}
            response_data['data'] = cr_entry
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiAccountConsentStatusLast(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, consent_id):
        """
        Fetch last Consent Status Record
        
        :param account_id: 
        :param consent_id: 
        :return: 
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, consent_id=consent_id))
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

        # Check path variables
        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Consent Record
        try:
            logger.info("Fetching Consent Record")
            cr = get_cr(cr_id=consent_id, account_id=account_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {} and Consent ID was {}.".format(account_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Get last Consent Status Record
        try:
            logger.info("Fetching last Consent Status Record")
            csr_dict = get_last_cr_status(consent_id=consent_id, account_id=account_id)
        except IndexError as exp:
            error_title = "Consent Status Record not found with provided information"
            error_detail = "Account ID was {} and Consent ID was {}".format(account_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Status Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Last Consent Status Record Fetched")
            logger.debug("Consent Status Record: " + json.dumps(csr_dict))

        # Response data container
        try:
            response_data = {}
            response_data['data'] = csr_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + json.dumps(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiAccountConsentStatusLastForServiceLinkRecord(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id, link_id, consent_id):
        """
        Fetch last Consent Status Record
        
        :param account_id: 
        :param consent_id: 
        :return: 
        """
        try:
            endpoint = str(api.url_for(self, account_id=account_id, link_id=link_id, consent_id=consent_id))
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

        # Check path variables
        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Consent Record
        try:
            logger.info("Fetching Consent Record")
            cr = get_cr(cr_id=consent_id, slr_id=link_id, account_id=account_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Account ID was {}, Service Link ID was {} and Consent ID was {}.".format(account_id, link_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Get last Consent Status Record
        try:
            logger.info("Fetching last Consent Status Record")
            csr_dict = get_last_cr_status(consent_id=consent_id, account_id=account_id)
        except IndexError as exp:
            error_title = "Consent Status Record not found with provided information"
            error_detail = "Account ID was {} and Consent ID was {}".format(account_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Status Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Last Consent Status Record Fetched")
            logger.debug("Consent Status Record: " + json.dumps(csr_dict))

        # Response data container
        try:
            response_data = {}
            response_data['data'] = csr_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + json.dumps(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)

######
# Service Section
#####


class ApiConsentsForService(Resource):
    @requires_api_auth_sdk
    def get(self, service_id, link_id):
        """
        Fetch list of Consent Records related to Service

        :param service_id:
        :param link_id:
        :return: JSON array
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

        # Check path variables
        try:
            service_id = str(service_id)
        except Exception as exp:
            error_title = "Unsupported service_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Get Consent Records
        try:
            logger.info("Fetching Consent Records")
            db_entries = get_crs(subject_id=service_id, slr_id=link_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Service ID was {} and Service Link ID was {}".format(service_id, link_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Records found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Records Fetched")
            logger.debug("Consent Records: " + json.dumps(db_entries))

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


class ApiConsentForService(Resource):
    @requires_api_auth_sdk
    def get(self, service_id, link_id, consent_id):
        """
        Fetch Consent Record related to Service

        :param service_id:
        :param link_id:
        :param consent_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, service_id=service_id, link_id=link_id, consent_id=consent_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        # Check path variables
        try:
            service_id = str(service_id)
        except Exception as exp:
            error_title = "Unsupported service_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Get Consent Record
        try:
            logger.info("Fetching Consent Record")
            cr_entry = get_cr(cr_id=consent_id, slr_id=link_id, subject_id=service_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Service ID was {}, Service Link ID was {} and Consent ID was {}.".format(service_id, link_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Response data container
        try:
            response_data = {}
            response_data['data'] = cr_entry
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiConsentStatusesForService(Resource):
    @requires_api_auth_sdk
    def get(self, service_id, link_id, consent_id):
        """
        Fetch list of Consent Status Records

        :param service_id:
        :param link_id:
        :param consent_id:
        :return: JSON array
        """
        try:
            endpoint = str(api.url_for(self, service_id=service_id, link_id=link_id, consent_id=consent_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        # Check path variables
        try:
            service_id = str(service_id)
        except Exception as exp:
            error_title = "Unsupported service_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Check query variables
        try:
            status_id = request.args.get('status_id', "")
            status_id = str(status_id)
        except Exception as exp:
            raise ApiError(code=400, title="Unsupported status_id", detail=repr(exp), source=endpoint)
        else:
            logger.info("status_id from query params: {}".format(status_id))

        # Get Consent Record
        try:
            logger.info("Fetching Consent Record")
            cr_entry = get_cr(cr_id=consent_id, slr_id=link_id, subject_id=service_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Service ID was {}, Service Link ID was {} and Consent ID was {}.".format(service_id, link_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Get Consent Status Records
        try:
            logger.info("Fetching Consent Status Records")
            db_entries = get_csrs(account_id="", consent_id=consent_id, status_id=status_id)
        except IndexError as exp:
            error_title = "Consent Status Records not found with provided information"
            error_detail = "Service ID was {}, Service Link ID was {} and Consent ID was {}. Status ID from query parameters was {}.".format(service_id, link_id, consent_id, status_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Status Records found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Status Records Fetched")

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


class ApiConsentStatusForService(Resource):
    @requires_api_auth_sdk
    def get(self, service_id, link_id, consent_id, status_id):
        """
        Fetch Consent Status Record

        :param service_id:
        :param link_id:
        :param consent_id:
        :param status_id:
        :return:
        """
        try:
            endpoint = str(api.url_for(self, service_id=service_id, link_id=link_id, consent_id=consent_id, status_id=status_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        # Check path variables
        try:
            service_id = str(service_id)
        except Exception as exp:
            error_title = "Unsupported service_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            status_id = str(status_id)
        except Exception as exp:
            error_title = "Unsupported status_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Get Consent Record
        try:
            logger.info("Fetching Consent Record")
            cr_entry = get_cr(cr_id=consent_id, slr_id=link_id, subject_id=service_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Service ID was {}, Service Link ID was {} and Consent ID was {}.".format(service_id, link_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Get Consent Status Record
        try:
            logger.info("Fetching Consent Record")
            cr_entry = get_csr(cr_id=consent_id, account_id="", csr_id=status_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Consent ID was {} and Consent Status ID was {}.".format(consent_id, status_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Response data container
        try:
            response_data = {}
            response_data['data'] = cr_entry
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiConsentStatusLastForService(Resource):
    @requires_api_auth_sdk
    def get(self, service_id, link_id, consent_id):
        """
        Fetch last Consent Status Record

        :param service_id: 
        :param link_id: 
        :param consent_id: 
        :return: 
        """
        try:
            endpoint = str(api.url_for(self, service_id=service_id, link_id=link_id, consent_id=consent_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching SDK API Key")
        api_key_sdk = get_sdk_api_key(endpoint=endpoint)
        logger.debug("api_key_sdk: " + api_key_sdk)

        # Check path variables
        try:
            service_id = str(service_id)
        except Exception as exp:
            error_title = "Unsupported service_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        try:
            link_id = str(link_id)
        except Exception as exp:
            error_title = "Unsupported link_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        try:
            consent_id = str(consent_id)
        except Exception as exp:
            error_title = "Unsupported consent_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Get Consent Record
        try:
            logger.info("Fetching Consent Record")
            cr = get_cr(cr_id=consent_id, subject_id=service_id, slr_id=link_id)
        except IndexError as exp:
            error_title = "Consent Record not found with provided information"
            error_detail = "Service ID was {}, Service Link ID was {} and Consent ID was {}.".format(service_id, link_id, consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Consent Record Fetched")

        # Get last Consent Status Record
        try:
            logger.info("Fetching last Consent Status Record")
            csr_dict = get_last_cr_status(consent_id=consent_id)
        except IndexError as exp:
            error_title = "Consent Status Record not found with provided information"
            error_detail = "Consent ID was {}".format(consent_id)
            logger.error(error_title + " - " + error_detail + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "No Consent Status Record found"
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Last Consent Status Record Fetched")
            logger.debug("Consent Status Record: " + json.dumps(csr_dict))

        # Response data container
        try:
            response_data = {}
            response_data['data'] = csr_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + json.dumps(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


# Register resources
api.add_resource(
    ApiAccountConsent,
    '/accounts/<string:account_id>/servicelinks/<string:source_link_id>/<string:sink_link_id>/consents',
    '/accounts/<string:account_id>/servicelinks/<string:source_link_id>/<string:sink_link_id>/consents/',
    endpoint='authorisation_give_consent'
)

api.add_resource(
    ApiAccountConsentStatus,
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses',
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses/',
    endpoint='authorisation_consent_status'
)

api.add_resource(
    ApiAccountConsentStatusSigned,
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses/signed',
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses/signed/',
    endpoint='authorisation_consent_status_signed'
)

api.add_resource(
    ApiConsentsForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/',
    endpoint='authorisation_account_link_consents'
)

api.add_resource(
    ApiConsentForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/',
    endpoint='authorisation_account_link_consent'
)

api.add_resource(
    ApiLastConsentForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/last',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/last/',
    endpoint='authorisation_account_link_last_consent'
)

api.add_resource(
    ApiConsentStatusesForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/',
    endpoint='authorisation_account_link_consent_statuses'
)

api.add_resource(
    ApiConsentStatusForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/<string:status_id>',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/<string:status_id>/',
    endpoint='authorisation_account_link_consent_status'
)

api.add_resource(
    ApiAccountConsentStatusLastForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/last',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/last/',
    endpoint='authorisation_account_link_consent_status_last'
)

api.add_resource(
    ApiConsentsForAccount,
    '/accounts/<string:account_id>/consents',
    '/accounts/<string:account_id>/consents/',
    endpoint='authorisation_account_consents'
)

api.add_resource(
    ApiConsentForAccount,
    '/accounts/<string:account_id>/consents/<string:consent_id>',
    '/accounts/<string:account_id>/consents/<string:consent_id>/',
    endpoint='authorisation_account_consent'
)

api.add_resource(
    ApiConsentStatusesForAccount,
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses',
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses/',
    endpoint='authorisation_account_consent_statuses'
)

api.add_resource(
    ApiConsentStatusForAccount,
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses/<string:status_id>',
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses/<string:status_id>/',
    endpoint='authorisation_account_consent_status'
)

api.add_resource(
    ApiAccountConsentStatusLast,
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses/last',
    '/accounts/<string:account_id>/consents/<string:consent_id>/statuses/last/',
    endpoint='authorisation_account_consent_status_last'
)

## For Service


api.add_resource(
    ApiConsentsForService,
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents',
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents/',
    endpoint='authorisation_service_consents'
)

api.add_resource(
    ApiConsentForService,
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents/<string:consent_id>',
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/',
    endpoint='authorisation_service_consent'
)

api.add_resource(
    ApiConsentStatusesForService,
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses',
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/',
    endpoint='authorisation_service_consent_statuses'
)

api.add_resource(
    ApiConsentStatusForService,
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/<string:status_id>',
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/<string:status_id>/',
    endpoint='authorisation_service_consent_status'
)

api.add_resource(
    ApiConsentStatusLastForService,
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/last',
    '/services/<string:service_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/last/',
    endpoint='authorisation_service_consent_status_last'
)



#api.add_resource(AuthorizationTokenData, '/consents/<string:sink_cr_id>/authorizationtoken/', endpoint='mydata-authorizationtoken')

