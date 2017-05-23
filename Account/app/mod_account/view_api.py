# -*- coding: utf-8 -*-

# Import dependencies
import json

# Import flask dependencies
from _mysql_exceptions import IntegrityError
from flask import Blueprint, request
from flask_restful import Resource, Api

# Import services
from app.helpers import get_custom_logger, make_json_response, ApiError, validate_json, compare_str_ids
from app.mod_account.controllers import verify_account_id_match, get_event_log, get_event_logs, \
    get_slrs, get_slr, get_slsrs, get_slsr, get_cr, get_crs, get_csrs, get_csr, export_account, create_account, \
    delete_account, get_account, get_account_infos, get_account_info, update_account_info
# from app.mod_account.models import AccountSchema2, ParticularsSchema, ContactsSchema, ContactsSchemaForUpdate, \
#     EmailsSchema, EmailsSchemaForUpdate, TelephonesSchema, TelephonesSchemaForUpdate, SettingsSchema, \
#     SettingsSchemaForUpdate
from app.mod_account.schemas import schema_account_new, schema_account_info
from app.mod_api_auth.controllers import requires_api_auth_user, provide_api_key, get_user_api_key

mod_account_api = Blueprint('account_api', __name__, template_folder='templates')
account_api = Api(mod_account_api)

# create logger with 'spam_application'
logger = get_custom_logger(__name__)


# Resources
class Accounts(Resource):
    def post(self):
        """
        """

        try:
            endpoint = str(account_api.url_for(self))
        except Exception as exp:
            endpoint = str(__name__)

        # load JSON
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        validate_json(json_data, schema_account_new)

        # Get elements from payload
        try:
            logger.info("Getting required data from payload")
            username = json_data['data']['attributes']['username']
            password = json_data['data']['attributes']['password']
            first_name = json_data['data']['attributes']['firstname']
            last_name = json_data['data']['attributes']['lastname']
        except Exception as exp:
            error_title = "Could not get required data from payload"
            error_detail = str(exp.__class__.__name__) + " - " + str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Got required data from payload")
            logger.debug("username from payload: " + username)
            logger.debug("password from payload: " + password)
            logger.debug("first_name from payload: " + first_name)
            logger.debug("last_name from payload: " + last_name)
            logger.debug("last_name from payload: " + last_name)

        try:
            account_object = create_account(
                first_name=first_name,
                last_name=last_name,
                username=username,
                password=password,
                endpoint=endpoint
            )
        except IntegrityError as exp:
            error_title = "Could not create Account"
            error_detail = "Username {} already exists".format(username)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=409, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "Could not create Account"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)

        # Response data container
        try:
            response_data = {}
            response_data['data'] = account_object.to_api_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=201)


class Account(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Account
        try:
            logger.info("Fetching Account")
            account_object = get_account(account_id=account_id)
        except Exception as exp:
            error_title = "No Account found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Account Fetched")
            logger.debug("Account object: " + account_object.log_entry)

        # Response data container
        try:
            response_data = {}
            response_data['data'] = account_object.to_api_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class AccountDelete(Resource):
    @requires_api_auth_user
    def delete(self, account_id):
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Delete Account
        try:
            logger.info("Deleting Account")
            delete_account(account_id=account_id)
        except Exception as exp:
            error_title = "Could not delete Account completely"
            logger.error(error_title + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Account Deleted")

        # Response data container
        try:
            response_data = {}
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=204)


class AccountExport(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Account Export
        try:
            logger.info("Exporting Account")
            db_entries = export_account(account_id=account_id)
        except Exception as exp:
            error_title = "Account Export failed"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Account Export Succeed")

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


class AccountInfos(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get AccountInfo
        try:
            logger.info("Fetching AccountInfo objects")
            db_entries = get_account_infos(account_id=account_id)
        except IndexError as exp:
            error_title = "AccountInfo not found with provided information"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "Could not find AccountInfo entry"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("AccountInfo objects Fetched")
            logger.info("AccountInfo objects: ")

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


class AccountInfo(Resource):
    @requires_api_auth_user
    def get(self, account_id, info_id):
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, info_id=info_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            info_id = str(info_id)
        except Exception as exp:
            error_title = "Unsupported info_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=str(exp.message), source=endpoint)
        else:
            logger.info("info_id: " + info_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get AccountInfo
        try:
            logger.info("Fetching AccountInfo")
            account_info_dict = get_account_info(account_id=account_id, id=info_id)
        except IndexError as exp:
            error_title = "AccountInfo not found with provided information"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "Could not fetch AccountInfo entry"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("AccountInfo Fetched")
            logger.debug("Accountinfo: " + json.dumps(account_info_dict))

        # Response data container
        try:
            response_data = {}
            response_data['data'] = account_info_dict
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
    def patch(self, account_id, info_id):
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, info_id=info_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            info_id = str(info_id)
        except Exception as exp:
            error_title = "Unsupported info_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("info_id: " + info_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # load JSON
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        validate_json(json_data, schema_account_info)

        # Get elements from payload
        try:
            logger.info("Getting required data from payload")
            attributes = json_data['data']['attributes']
            account_info_id = str(json_data['data']['id'])
        except Exception as exp:
            error_title = "Could not get required data from payload"
            error_detail = str(exp.__class__.__name__) + " - " + str(exp.message)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("Got required data from payload")
            logger.debug("attributes from payload: " + json.dumps(attributes))
            logger.debug("account_info_id from payload: " + account_info_id)

        try:
            logger.info("Verifying that AccountInfo IDs from path and payload are matching")
            compare_str_ids(id=info_id, id_to_compare=account_info_id)
        except ValueError as exp:
            error_title = "AccountInfo IDs from path and payload are not matching"
            error_detail = "SLR ID from path was {} and from payload {}".format(info_id, account_info_id)
            logger.error(error_title + " - " + error_detail + ": " + str(exp.message))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("AccountInfo IDs from path and payload are matching")

        # Update AccountInfo
        try:
            logger.info("Updating AccountInfo")
            account_info_object = update_account_info(account_id=account_id, id=info_id, attributes=attributes)
        except IndexError as exp:
            error_title = "AccountInfo not found with provided information"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=400, title=error_title, detail=error_detail, source=endpoint)
        except Exception as exp:
            error_title = "Could not update AccountInfo entry"
            error_detail = str(exp.message)
            logger.error(error_title + " - " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=error_detail, source=endpoint)
        else:
            logger.info("AccountInfo Updated")
            logger.debug("AccountInfo: " + account_info_object.log_entry)

        # Response data container
        try:
            response_data = {}
            response_data['data'] = account_info_object.to_api_dict
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)



class AccountEventLogs(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        logger.info("AccountEventLogs")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get EventLog
        try:
            logger.info("Fetching EventLog")
            db_entries = get_event_logs(account_id=account_id)
        except Exception as exp:
            error_title = "No EventLog found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("EventLog Fetched")

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


class AccountEventLog(Resource):
    @requires_api_auth_user
    def get(self, account_id, event_log_id):
        logger.info("AccountEventLog")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, event_log_id=event_log_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            event_log_id = str(event_log_id)
        except Exception as exp:
            error_title = "Unsupported event_log_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("event_log_id: " + event_log_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get EventLog
        try:
            logger.info("Fetching EventLog")
            db_entries = get_event_log(account_id=account_id, id=event_log_id)
        except Exception as exp:
            error_title = "No EventLog found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("EventLog Fetched")

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


class AccountServiceLinkRecords(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        logger.info("AccountServiceLinkRecords")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkRecords
        try:
            logger.info("Fetching ServiceLinkRecords")
            db_entries = get_slrs(account_id=account_id)
        except Exception as exp:
            error_title = "No ServiceLinkRecords found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
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


class AccountServiceLinkRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, slr_id):
        logger.info("AccountServiceLinkRecord")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, slr_id=slr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            slr_id = str(slr_id)
        except Exception as exp:
            error_title = "Unsupported slr_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("slr_id: " + slr_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkRecord
        try:
            logger.info("Fetching ServiceLinkRecord")
            db_entries = get_slr(account_id=account_id, slr_id=slr_id)
        except Exception as exp:
            error_title = "No ServiceLinkRecord found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
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


class AccountServiceLinkStatusRecords(Resource):
    @requires_api_auth_user
    def get(self, account_id, slr_id):
        logger.info("AccountServiceLinkStatusRecords")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, slr_id=slr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            slr_id = str(slr_id)
        except Exception as exp:
            error_title = "Unsupported slr_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("slr_id: " + slr_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkStatusRecords
        try:
            logger.info("Fetching ServiceLinkStatusRecords")
            db_entries = get_slsrs(account_id=account_id, slr_id=slr_id)
        except StandardError as exp:
            error_title = "ServiceLinkStatusRecords not accessible"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=403, title=error_title, detail=repr(exp), source=endpoint)
        except Exception as exp:
            error_title = "No ServiceLinkStatusRecords found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
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


class AccountServiceLinkStatusRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, slr_id, slsr_id):
        logger.info("AccountServiceLinkStatusRecord")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, slr_id=slr_id, slsr_id=slsr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            slr_id = str(slr_id)
        except Exception as exp:
            error_title = "Unsupported slr_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("slr_id: " + slr_id)

        try:
            slsr_id = str(slsr_id)
        except Exception as exp:
            error_title = "Unsupported slsr_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("slsr_id: " + slsr_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkStatusRecord
        try:
            logger.info("Fetching ServiceLinkStatusRecord")
            db_entries = get_slsr(account_id=account_id, slr_id=slr_id, slsr_id=slsr_id)
        except StandardError as exp:
            error_title = "ServiceLinkStatusRecords not accessible"
            logger.error(error_title + repr(exp))
            raise ApiError(code=403, title=error_title, detail=repr(exp), source=endpoint)
        except Exception as exp:
            error_title = "No tServiceLinkStatusRecord found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
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


class AccountConsentRecords(Resource):
    @requires_api_auth_user
    def get(self, account_id, slr_id):
        logger.info("AccountConsentRecords")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, slr_id=slr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            slr_id = str(slr_id)
        except Exception as exp:
            error_title = "Unsupported slr_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("slr_id: " + slr_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ConsentRecords
        try:
            logger.info("Fetching ConsentRecords")
            db_entries = get_crs(account_id=account_id, slr_id=slr_id)
        except StandardError as exp:
            error_title = "ConsentRecords not accessible"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=403, title=error_title, detail=repr(exp), source=endpoint)
        except Exception as exp:
            error_title = "No ConsentRecords found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("ConsentRecords Fetched")

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


class AccountConsentRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, slr_id, cr_id):
        logger.info("AccountConsentRecord")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, slr_id=slr_id, cr_id=cr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            slr_id = str(slr_id)
        except Exception as exp:
            error_title = "Unsupported slr_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("slr_id: " + slr_id)

        try:
            cr_id = str(cr_id)
        except Exception as exp:
            error_title = "Unsupported cr_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("cr_id: " + cr_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkStatusRecord
        try:
            logger.info("Fetching ConsentRecord")
            db_entries = get_cr(account_id=account_id, slr_id=slr_id, cr_id=cr_id)
        except StandardError as exp:
            error_title = "ConsentRecord not accessible"
            logger.error(error_title + repr(exp))
            raise ApiError(code=403, title=error_title, detail=repr(exp), source=endpoint)
        except Exception as exp:
            error_title = "No ConsentRecord found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("ConsentRecord Fetched")

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


class AccountConsentStatusRecords(Resource):
    @requires_api_auth_user
    def get(self, account_id, slr_id, cr_id):
        logger.info("AccountConsentStatusRecords")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, slr_id=slr_id, cr_id=cr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            slr_id = str(slr_id)
        except Exception as exp:
            error_title = "Unsupported slr_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("slr_id: " + slr_id)

        try:
            cr_id = str(cr_id)
        except Exception as exp:
            error_title = "Unsupported cr_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("cr_id: " + cr_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ConsentStatusRecords
        try:
            logger.info("Fetching ConsentStatusRecords")
            db_entries = get_csrs(account_id=account_id, slr_id=slr_id, cr_id=cr_id)
        except StandardError as exp:
            error_title = "ConsentStatusRecords not accessible"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=403, title=error_title, detail=repr(exp), source=endpoint)
        except Exception as exp:
            error_title = "No ConsentStatusRecords found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("ConsentStatusRecords Fetched")

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


class AccountConsentStatusRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, slr_id, cr_id, csr_id):
        logger.info("AccountConsentStatusRecord")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, slr_id=slr_id, cr_id=cr_id, csr_id=csr_id))
        except Exception as exp:
            endpoint = str(__name__)

        try:
            logger.info("Fetching Api-Key from Headers")
            api_key = request.headers.get('Api-Key-User')
        except Exception as exp:
            logger.error("No ApiKey in headers: " + repr(repr(exp)))
            return provide_api_key(endpoint=endpoint)
        else:
            logger.info("Api-Key: " + api_key)

        try:
            account_id = str(account_id)
        except Exception as exp:
            error_title = "Unsupported account_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("account_id: " + account_id)

        try:
            slr_id = str(slr_id)
        except Exception as exp:
            error_title = "Unsupported slr_id"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("slr_id: " + slr_id)

        try:
            cr_id = str(cr_id)
        except Exception as exp:
            error_title = "Unsupported cr_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("cr_id: " + cr_id)

        try:
            csr_id = str(csr_id)
        except Exception as exp:
            error_title = "Unsupported csr_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("csr_id: " + csr_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ConsentStatusRecord
        try:
            logger.info("Fetching ConsentStatusRecord")
            db_entries = get_csr(account_id=account_id, slr_id=slr_id, cr_id=cr_id, csr_id=csr_id)
        except StandardError as exp:
            error_title = "ConsentStatusRecord not accessible"
            logger.error(error_title + repr(exp))
            raise ApiError(code=403, title=error_title, detail=repr(exp), source=endpoint)
        except Exception as exp:
            error_title = "No ConsentStatusRecord found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("ConsentStatusRecord Fetched")

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

# Register resources
account_api.add_resource(
    Accounts,
    '/accounts',
    '/accounts/',
    endpoint='accounts'
)

account_api.add_resource(
    Account,
    '/accounts/<string:account_id>',
    '/accounts/<string:account_id>/',
    endpoint='account-get'
)

account_api.add_resource(
    AccountDelete,
    '/accounts/<string:account_id>',
    '/accounts/<string:account_id>/',
    endpoint='account-delete'
)

account_api.add_resource(
    AccountExport,
    '/accounts/<string:account_id>/export',
    '/accounts/<string:account_id>/export/',
    endpoint='account-export'
)

account_api.add_resource(
    AccountInfos,
    '/accounts/<string:account_id>/info',
    '/accounts/<string:account_id>/info/',
    endpoint='account-infos'
)

account_api.add_resource(
    AccountInfo,
    '/accounts/<string:account_id>/info/<string:info_id>',
    '/accounts/<string:account_id>/info/<string:info_id>/',
    endpoint='account-info'
)

account_api.add_resource(
    AccountEventLogs,
    '/accounts/<string:account_id>/logs/events/',
    '/accounts/<string:account_id>/logs/events',
    endpoint='account-events'
)

account_api.add_resource(
    AccountEventLog,
    '/accounts/<string:account_id>/logs/events/<string:event_log_id>/',
    '/accounts/<string:account_id>/logs/events/<string:event_log_id>',
    endpoint='account-event'
)

account_api.add_resource(
    AccountServiceLinkRecords,
    '/accounts/<string:account_id>/servicelinks/',
    '/accounts/<string:account_id>/servicelinks',
    endpoint='account-slrs'
)

account_api.add_resource(
    AccountServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/',
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>',
    endpoint='account-slr'
)

account_api.add_resource(
    AccountServiceLinkStatusRecords,
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/statuses/',
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/statuses',
    endpoint='account-slsrs'
)

account_api.add_resource(
    AccountServiceLinkStatusRecord,
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/statuses/<string:slsr_id>/',
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/statuses/<string:slsr_id>',
    endpoint='account-slsr'
)

account_api.add_resource(
    AccountConsentRecords,
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/consents/',
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/consents',
    endpoint='account-crs'
)

account_api.add_resource(
    AccountConsentRecord,
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/consents/<string:cr_id>/',
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/consents/<string:cr_id>',
    endpoint='account-cr'
)

account_api.add_resource(
    AccountConsentStatusRecords,
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/consents/<string:cr_id>/statuses/',
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/consents/<string:cr_id>/statuses',
    endpoint='account-csrs'
)

account_api.add_resource(
    AccountConsentStatusRecord,
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/consents/<string:cr_id>/statuses/<string:csr_id>/',
    '/accounts/<string:account_id>/servicelinks/<string:slr_id>/consents/<string:cr_id>/statuses/<string:csr_id>',
    endpoint='account-csr'
)



