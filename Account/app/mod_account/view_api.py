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
import json

# Import flask dependencies
from _mysql_exceptions import IntegrityError
from flask import Blueprint, request
from flask_restful import Resource, Api

# Import services
from app.helpers import get_custom_logger, make_json_response, ApiError, validate_json, compare_str_ids, get_utc_time
from app.mod_account.controllers import verify_account_id_match, get_event_log, get_event_logs, export_account, \
    create_account, delete_account, get_account, get_account_infos, get_account_info, update_account_info, \
    account_get_slrs, account_get_slr, account_get_slsrs, account_get_slsr, account_get_last_slr_status, \
    account_get_crs, account_get_cr, account_get_last_cr, account_get_csrs, account_get_csr, account_get_last_cr_status
# from app.mod_account.models import AccountSchema2, ParticularsSchema, ContactsSchema, ContactsSchemaForUpdate, \
#     EmailsSchema, EmailsSchemaForUpdate, TelephonesSchema, TelephonesSchemaForUpdate, SettingsSchema, \
#     SettingsSchemaForUpdate
from app.mod_account.schemas import schema_account_new, schema_account_info
from app.mod_api_auth.controllers import requires_api_auth_user, provide_api_key, get_user_api_key
from app.mod_database.controllers import create_event_log_entry

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
            account_object, account_id = create_account(
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="POST",
            resource=endpoint,
            timestamp=get_utc_time()
        )

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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

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
            response_data = {}
            response_data['data'] = db_entries
        except Exception as exp:
            logger.error('Could not prepare response data: ' + repr(exp))
            raise ApiError(code=500, title="Could not prepare response data", detail=repr(exp), source=endpoint)
        else:
            logger.info('Response data ready')
            logger.debug('response_data: ' + repr(response_data))

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="PATCH",
            resource=endpoint,
            timestamp=get_utc_time()
        )

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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


####################
# MyData endpoints #
####################

class ApiServiceLinkRecords(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        """
        Fetch list of Service Link Records

        :param account_id:
        :return: JSON array
        """
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
            raise ApiError(code=400, title="Unsupported account_id", detail=repr(exp), source=endpoint)
        else:
            logger.debug("Account ID from path: " + account_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key_user, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get ServiceLinkRecords
        try:
            logger.info("Fetching ServiceLinkRecords")
            db_entries = account_get_slrs(account_id=account_id)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiServiceLinkRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, link_id):
        """
        Fetch Service Link Record by Service Link ID

        :param account_id:
        :param slr_id:
        :return:
        """
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id))
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
            db_entries = account_get_slr(account_id=account_id, slr_id=link_id)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiServiceLinkStatusRecords(Resource):
    @requires_api_auth_user
    def get(self, account_id, link_id):
        """
        Fetch list of Service Link Status Records

        :param account_id:
        :param link_id:
        :return: JSON array
        """
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id))
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
            db_entries = account_get_slsrs(account_id=account_id, slr_id=link_id)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiServiceLinkStatusRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, link_id, status_id):
        """
        Fetch Service Link Status Record by ID

        :param account_id:
        :param link_id:
        :param status_id:
        :return:
        """
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id, status_id=status_id))
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
            db_entries = account_get_slsr(account_id=account_id, slr_id=link_id, slsr_id=status_id)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiLastServiceLinkStatusRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, link_id):
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id))
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
            last_slsr_dict = account_get_last_slr_status(account_id=account_id, slr_id=link_id, endpoint=endpoint)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


###
# Consents
###
class ApiConsentsForServiceLinkRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, link_id):
        """
        List Consent Records related to Service Link Record

        :param account_id:
        :param link_id:
        :return: JSON array
        """
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

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
            db_entries = account_get_crs(slr_id=link_id, account_id=account_id, consent_pairs=get_consent_pair)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiConsentForServiceLinkRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, link_id, consent_id):
        """
        Fetch Consent Record related to Service Link Record

        :param account_id:
        :param link_id:
        :param consent_id:
        :return:
        """
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id, consent_id=consent_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

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
            cr_array.append(account_get_cr(cr_id=consent_id, slr_id=link_id, account_id=account_id))
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
                cr_array.append(account_get_cr(account_id=account_id, consent_pair_id=consent_id))
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiLastConsentForServiceLinkRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, link_id):
        """
        Fetch Last Consent Record related to Service Link Record

        :param account_id:
        :param link_id:
        :return:
        """
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

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
            cr_array = account_get_last_cr(slr_id=link_id, account_id=account_id, consent_pairs=get_consent_pair)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiConsentStatusesForServiceLinkRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, link_id, consent_id):
        """
        Fetch list of Consent Status Records

        :param account_id:
        :param link_id:
        :param consent_id:
        :return: JSON array
        """
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id, consent_id=consent_id))
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
            cr = account_get_cr(cr_id=consent_id, slr_id=link_id, account_id=account_id)
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
            db_entries = account_get_csrs(account_id=account_id, consent_id=consent_id, status_id=status_id)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiConsentStatusForServiceLinkRecord(Resource):
    @requires_api_auth_user
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
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id, consent_id=consent_id, status_id=status_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

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
            cr = account_get_cr(cr_id=consent_id, slr_id=link_id, account_id=account_id)
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
            cr_entry = account_get_csr(cr_id=consent_id, account_id=account_id, csr_id=status_id)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + repr(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class ApiAccountConsentStatusLastForServiceLinkRecord(Resource):
    @requires_api_auth_user
    def get(self, account_id, link_id, consent_id):
        """
        Fetch last Consent Status Record
        
        :param account_id: 
        :param consent_id: 
        :return: 
        """
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, link_id=link_id, consent_id=consent_id))
        except Exception as exp:
            endpoint = str(__name__)
        finally:
            logger.info("Request to: " + str(endpoint))

        logger.info("Fetching User API Key")
        api_key_user = get_user_api_key(endpoint=endpoint)
        logger.debug("api_key_user: " + api_key_user)

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
            cr = account_get_cr(cr_id=consent_id, slr_id=link_id, account_id=account_id)
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
            csr_dict = account_get_last_cr_status(consent_id=consent_id, account_id=account_id)
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

        create_event_log_entry(
            account_id=account_id,
            actor="AccountOwner",
            action="GET",
            resource=endpoint,
            timestamp=get_utc_time()
        )

        response_data_dict = dict(response_data)
        logger.debug('response_data_dict: ' + json.dumps(response_data_dict))
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
    '/accounts/<string:account_id>/logs/events',
    '/accounts/<string:account_id>/logs/events/',
    endpoint='account-events'
)

account_api.add_resource(
    AccountEventLog,
    '/accounts/<string:account_id>/logs/events/<string:event_log_id>',
    '/accounts/<string:account_id>/logs/events/<string:event_log_id>/',
    endpoint='account-event'
)

account_api.add_resource(
    ApiServiceLinkRecords,
    '/accounts/<string:account_id>/servicelinks',
    '/accounts/<string:account_id>/servicelinks/',
    endpoint='account-slrs'
)

account_api.add_resource(
    ApiServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/',
    endpoint='account-slr'
)

account_api.add_resource(
    ApiServiceLinkStatusRecords,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses/',
    endpoint='account-slsrs'
)

account_api.add_resource(
    ApiServiceLinkStatusRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses/<string:status_id>',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses/<string:status_id>/',
    endpoint='account-slsr'
)

account_api.add_resource(
    ApiLastServiceLinkStatusRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses/last',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/statuses/last/',
    endpoint='account-slsr-last'
)

account_api.add_resource(
    ApiConsentsForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/',
    endpoint='account-crs'
)

account_api.add_resource(
    ApiConsentForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/',
    endpoint='account-cr'
)

account_api.add_resource(
    ApiLastConsentForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/last',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/last/',
    endpoint='account-cr-last'
)

account_api.add_resource(
    ApiConsentStatusesForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/',
    endpoint='account-csrs'
)

account_api.add_resource(
    ApiConsentStatusForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/<string:status_id>',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/<string:status_id>/',
    endpoint='account-csr'
)

account_api.add_resource(
    ApiLastConsentForServiceLinkRecord,
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/last',
    '/accounts/<string:account_id>/servicelinks/<string:link_id>/consents/<string:consent_id>/statuses/last/',
    endpoint='account-csr-last'
)



