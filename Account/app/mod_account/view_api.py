# -*- coding: utf-8 -*-

# Import dependencies
import json

# Import flask dependencies
from flask import Blueprint, request
from flask_restful import Resource, Api

# Import services
from app.helpers import get_custom_logger, make_json_response, ApiError
from app.mod_account.controllers import get_particulars, get_particular, verify_account_id_match, \
    update_particular, get_event_log, get_event_logs, get_slrs, get_slr, get_slsrs, get_slsr, get_cr, \
    get_crs, get_csrs, get_csr, export_account, create_account, delete_account, update_setting, get_contacts, \
    add_contact, get_contact, update_contact, get_emails, add_email, get_email, get_telephones, add_telephone, \
    update_telephone, get_settings, add_setting, update_email, get_telephone, get_setting, get_account
from app.mod_account.models import AccountSchema2, ParticularsSchema, ContactsSchema, ContactsSchemaForUpdate, \
    EmailsSchema, EmailsSchemaForUpdate, TelephonesSchema, TelephonesSchemaForUpdate, SettingsSchema, \
    SettingsSchemaForUpdate
from app.mod_api_auth.controllers import requires_api_auth_user, provide_api_key

mod_account_api = Blueprint('account_api', __name__, template_folder='templates')
account_api = Api(mod_account_api)

# create logger with 'spam_application'
logger = get_custom_logger(__name__)


# Resources
class Accounts(Resource):
    def post(self):
        """
        Example JSON
        {
            "data": {
                "type": "Account",
                "attributes": {
                    'firstName': 'Erkki',
                    'lastName': 'Esimerkki',
                    'dateOfBirth': '2016-05-31',
                    'email': 'erkki.esimerkki@examlpe.org',
                    'username': 'testUser',
                    'password': 'Hello',
                    'acceptTermsOfService': 'True'
                }
            }
        }
        :return:
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
        schema = AccountSchema2()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors), source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        try:
            username = json_data['data']['attributes']['username']
            password = json_data['data']['attributes']['password']
            first_name = json_data['data']['attributes']['firstName']
            last_name = json_data['data']['attributes']['lastName']
            email_address = json_data['data']['attributes']['email']
            date_of_birth = json_data['data']['attributes']['dateOfBirth']
        except Exception as exp:
            error_title = "Could not prepare Account data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        try:
            account_id = create_account(
                first_name=first_name,
                last_name=last_name,
                username=username,
                password=password,
                email_address=email_address,
                date_of_birth=date_of_birth,
                endpoint=endpoint
            )
        except ApiError as exp:
            error_title = "Could not create Account"
            logger.error(error_title + ': ' + repr(exp))
            raise
        except Exception as exp:
            error_title = "Could not create Account"
            logger.debug(error_title + ': ' + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)

        # Response data container
        try:
            response_data = {}
            response_data['meta'] = {}
            response_data['meta']['activationInstructions'] = "Account activated already"

            response_data['data'] = {}
            response_data['data']['type'] = "Account"
            response_data['data']['id'] = account_id
            response_data['data']['attributes'] = json_data['data']['attributes']
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
        logger.info("Account")
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

        # Get Particulars
        try:
            logger.info("Fetching Account")
            db_entries = get_account(account_id=account_id)
        except Exception as exp:
            error_title = "No Account found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Account Fetched")

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


class AccountDelete(Resource):
    # TODO: Account reactivation
    # TODO: Create Account with same credentials
    @requires_api_auth_user
    def delete(self, account_id):
        logger.info("AccountDelete")
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
        logger.info("AccountExport")
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


class AccountParticulars(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        logger.info("AccountParticulars")
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

        # Get Particulars
        try:
            logger.info("Fetching Particulars")
            db_entries = get_particulars(account_id=account_id)
        except Exception as exp:
            error_title = "No Particulars found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Particulars Fetched")
            logger.info("Particulars: ")

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


class AccountParticular(Resource):
    @requires_api_auth_user
    def get(self, account_id, particulars_id):
        logger.info("AccountParticulars")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, particulars_id=particulars_id))
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
            particulars_id = str(particulars_id)
        except Exception as exp:
            error_title = "Unsupported particulars_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("particulars_id: " + particulars_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Particulars
        try:
            logger.info("Fetching Particulars")
            db_entries = get_particular(account_id=account_id, id=particulars_id)
        except Exception as exp:
            error_title = "No Particulars found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Particulars Fetched")

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
    def patch(self, account_id, particulars_id):
        logger.info("AccountParticular")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, particulars_id=particulars_id))
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
            particulars_id = str(particulars_id)
        except Exception as exp:
            error_title = "Unsupported particulars_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("particulars_id: " + particulars_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs from path and ApiKey are matching")

        # load JSON from payload
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = ParticularsSchema()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors), source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        try:
            particulars_id_from_payload = json_data['data'].get("id", "")
        except Exception as exp:
            error_title = "Could not get id from payload"
            logger.error(error_title)
            raise ApiError(
                code=404,
                title=error_title,
                detail=repr(exp),
                source=endpoint
            )

        # Check if particulars_id from path and payload are matching
        if particulars_id != particulars_id_from_payload:
            error_title = "Particulars IDs from path and payload are not matching"
            compared_ids = {'IdFromPath': particulars_id, 'IdFromPayload': particulars_id_from_payload}
            logger.error(error_title + ", " + json.dumps(compared_ids))
            raise ApiError(
                code=403,
                title=error_title,
                detail=compared_ids,
                source=endpoint
            )
        else:
            logger.info("Particulars IDs from path and payload are matching")

        # Collect data
        try:
            attributes = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not collect data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Update Particulars
        try:
            logger.info("Updating Particulars")
            db_entries = update_particular(account_id=account_id, id=particulars_id, attributes=attributes)
        except Exception as exp:
            error_title = "No Particulars found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Particulars Updated")

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


class AccountContacts(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        logger.info("AccountContacts")
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

        # Get Contacts
        try:
            logger.info("Fetching Contacts")
            db_entries = get_contacts(account_id=account_id)
        except Exception as exp:
            error_title = "No Contacts found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Contacts Fetched")

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
    def post(self, account_id):
        logger.info("AccountContacts")
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
            logger.info("Account IDs from path and ApiKey are matching")

        # load JSON from payload
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = ContactsSchema()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors),
                           source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        # Collect data
        try:
            attributes = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not collect data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Add Contact
        try:
            logger.info("Adding Contacts")
            db_entries = add_contact(account_id=account_id, attributes=attributes)
        except Exception as exp:
            error_title = "Could not add Contact entry"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Contacts Updated")

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
        return make_json_response(data=response_data_dict, status_code=201)


class AccountContact(Resource):
    @requires_api_auth_user
    def get(self, account_id, contacts_id):
        logger.info("AccountContact")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, contacts_id=contacts_id))
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
            contacts_id = str(contacts_id)
        except Exception as exp:
            error_title = "Unsupported contacts_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("contacts_id: " + contacts_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Contacts
        try:
            logger.info("Fetching Contacts")
            db_entries = get_contact(account_id=account_id, id=contacts_id)
        except Exception as exp:
            error_title = "No Contacts found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Contacts Fetched")

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
    def patch(self, account_id, contacts_id):  # TODO: Should be PATCH instead of PUT
        logger.info("AccountContact")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, contacts_id=contacts_id))
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
            contacts_id = str(contacts_id)
        except Exception as exp:
            error_title = "Unsupported contacts_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("contacts_id: " + contacts_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs from path and ApiKey are matching")

        # load JSON from payload
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = ContactsSchemaForUpdate()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors), source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        try:
            contacts_id_from_payload = json_data['data'].get("id", "")
        except Exception as exp:
            error_title = "Could not get id from payload"
            logger.error(error_title)
            raise ApiError(
                code=404,
                title=error_title,
                detail=repr(exp),
                source=endpoint
            )

        # Check if contacts_id from path and payload are matching
        if contacts_id != contacts_id_from_payload:
            error_title = "Contact IDs from path and payload are not matching"
            compared_ids = {'IdFromPath': contacts_id, 'IdFromPayload': contacts_id_from_payload}
            logger.error(error_title + ", " + json.dumps(compared_ids))
            raise ApiError(
                code=403,
                title=error_title,
                detail=compared_ids,
                source=endpoint
            )
        else:
            logger.info("Contact IDs from path and payload are matching")

        # Collect data
        try:
            attributes = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not collect data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Update Contact
        try:
            logger.info("Updating Contacts")
            db_entries = update_contact(account_id=account_id, id=contacts_id, attributes=attributes)
        except Exception as exp:
            error_title = "No Contacts found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Contacts Updated")

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


class AccountEmails(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        logger.info("AccountEmails")
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

        # Get Emails
        try:
            logger.info("Fetching Emails")
            db_entries = get_emails(account_id=account_id)
        except Exception as exp:
            error_title = "No Emails found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Emails Fetched")

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
    def post(self, account_id):
        logger.info("AccountEmails")
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
            logger.info("Account IDs from path and ApiKey are matching")

        # load JSON from payload
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = EmailsSchema()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors),
                           source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        # Collect data
        try:
            attributes = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not collect data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Add Email
        try:
            logger.info("Adding Email")
            db_entries = add_email(account_id=account_id, attributes=attributes)
        except Exception as exp:
            error_title = "Could not add Email entry"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Email added")

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
        return make_json_response(data=response_data_dict, status_code=201)


class AccountEmail(Resource):
    @requires_api_auth_user
    def get(self, account_id, emails_id):
        logger.info("AccountEmail")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, emails_id=emails_id))
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
            emails_id = str(emails_id)
        except Exception as exp:
            error_title = "Unsupported emails_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("emails_id: " + emails_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Email
        try:
            logger.info("Fetching Email")
            db_entries = get_email(account_id=account_id, id=emails_id)
        except Exception as exp:
            error_title = "No Email found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Email Fetched")

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
    def patch(self, account_id, emails_id):  # TODO: Should be PATCH instead of PUT
        logger.info("AccountEmail")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, emails_id=emails_id))
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
            emails_id = str(emails_id)
        except Exception as exp:
            error_title = "Unsupported emails_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("emails_id: " + emails_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs from path and ApiKey are matching")

        # load JSON from payload
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = EmailsSchemaForUpdate()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors), source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        try:
            emails_id_from_payload = json_data['data'].get("id", "")
        except Exception as exp:
            error_title = "Could not get id from payload"
            logger.error(error_title)
            raise ApiError(
                code=404,
                title=error_title,
                detail=repr(exp),
                source=endpoint
            )

        # Check if emails_id from path and payload are matching
        if emails_id != emails_id_from_payload:
            error_title = "Email IDs from path and payload are not matching"
            compared_ids = {'IdFromPath': emails_id, 'IdFromPayload': emails_id_from_payload}
            logger.error(error_title + ", " + json.dumps(compared_ids))
            raise ApiError(
                code=403,
                title=error_title,
                detail=compared_ids,
                source=endpoint
            )
        else:
            logger.info("Email IDs from path and payload are matching")

        # Collect data
        try:
            attributes = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not collect data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Update Email
        try:
            logger.info("Updating Emails")
            db_entries = update_email(account_id=account_id, id=emails_id, attributes=attributes)
        except Exception as exp:
            # TODO: Error handling on more detailed level
            error_title = "No Email found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Email Updated")

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


class AccountTelephones(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        logger.info("AccountTelephones")
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

        # Get Telephones
        try:
            logger.info("Fetching Telephones")
            db_entries = get_telephones(account_id=account_id)
        except Exception as exp:
            error_title = "No Telephones found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Telephones Fetched")

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
    def post(self, account_id):
        logger.info("AccountTelephones")
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
            logger.info("Account IDs from path and ApiKey are matching")

        # load JSON from payload
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = TelephonesSchema()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors),
                           source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        # Collect data
        try:
            attributes = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not collect data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Add Telephone
        try:
            logger.info("Adding Telephone")
            db_entries = add_telephone(account_id=account_id, attributes=attributes)
        except Exception as exp:
            error_title = "Could not add Telephone entry"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Telephone added")

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
        return make_json_response(data=response_data_dict, status_code=201)


class AccountTelephone(Resource):
    @requires_api_auth_user
    def get(self, account_id, telephones_id):
        logger.info("AccountTelephone")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, telephones_id=telephones_id))
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
            telephones_id = str(telephones_id)
        except Exception as exp:
            error_title = "Unsupported telephones_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("telephones_id: " + telephones_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Telephone
        try:
            logger.info("Fetching Telephone")
            db_entries = get_telephone(account_id=account_id, id=telephones_id)
        except Exception as exp:
            error_title = "No Telephone found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Telephone Fetched")

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
    def patch(self, account_id, telephones_id):  # TODO: Should be PATCH instead of PUT
        logger.info("AccountTelephone")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, telephones_id=telephones_id))
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
            telephones_id = str(telephones_id)
        except Exception as exp:
            error_title = "Unsupported telephones_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("telephones_id: " + telephones_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs from path and ApiKey are matching")

        # load JSON from payload
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = TelephonesSchemaForUpdate()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors), source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        try:
            telephones_id_from_payload = json_data['data'].get("id", "")
        except Exception as exp:
            error_title = "Could not get id from payload"
            logger.error(error_title)
            raise ApiError(
                code=404,
                title=error_title,
                detail=repr(exp),
                source=endpoint
            )

        # Check if emails_id from path and payload are matching
        if telephones_id != telephones_id_from_payload:
            error_title = "Email IDs from path and payload are not matching"
            compared_ids = {'IdFromPath': telephones_id, 'IdFromPayload': telephones_id_from_payload}
            logger.error(error_title + ", " + json.dumps(compared_ids))
            raise ApiError(
                code=403,
                title=error_title,
                detail=compared_ids,
                source=endpoint
            )
        else:
            logger.info("Telephone IDs from path and payload are matching")

        # Collect data
        try:
            attributes = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not collect data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Update Telephone
        try:
            logger.info("Updating Telephone")
            db_entries = update_telephone(account_id=account_id, id=telephones_id, attributes=attributes)
        except Exception as exp:
            # TODO: Error handling on more detailed level
            error_title = "No Telephone found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Telephone Updated")

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


class AccountSettings(Resource):
    @requires_api_auth_user
    def get(self, account_id):
        logger.info("AccountSettings")
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

        # Get Settings
        try:
            logger.info("Fetching Settings")
            db_entries = get_settings(account_id=account_id)
        except Exception as exp:
            error_title = "No Settings found"
            logger.error(error_title + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Settings Fetched")

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
    def post(self, account_id):
        logger.info("AccountSettings")
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
            logger.info("Account IDs from path and ApiKey are matching")

        # load JSON from payload
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = SettingsSchema()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors),
                           source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        # Collect data
        try:
            attributes = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not collect data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Add Setting
        try:
            logger.info("Adding Setting")
            db_entries = add_setting(account_id=account_id, attributes=attributes)
        except Exception as exp:
            error_title = "Could not add Setting entry"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Setting added")

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
        return make_json_response(data=response_data_dict, status_code=201)


class AccountSetting(Resource):
    @requires_api_auth_user
    def get(self, account_id, settings_id):
        logger.info("AccountSetting")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, settings_id=settings_id))
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
            settings_id = str(settings_id)
        except Exception as exp:
            error_title = "Unsupported settings_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("settings_id: " + settings_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs are matching")

        # Get Setting
        try:
            logger.info("Fetching Setting")
            db_entries = get_setting(account_id=account_id, id=settings_id)
        except Exception as exp:
            error_title = "No Setting found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Setting Fetched")

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
    def patch(self, account_id, settings_id):  # TODO: Should be PATCH instead of PUT
        logger.info("AccountSetting")
        try:
            endpoint = str(account_api.url_for(self, account_id=account_id, settings_id=settings_id))
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
            settings_id = str(settings_id)
        except Exception as exp:
            error_title = "Unsupported settings_id"
            logger.error(error_title + repr(exp))
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("settings_id: " + settings_id)

        # Check if Account IDs from path and ApiKey are matching
        if verify_account_id_match(account_id=account_id, api_key=api_key, endpoint=endpoint):
            logger.info("Account IDs from path and ApiKey are matching")

        # load JSON from payload
        json_data = request.get_json()
        if not json_data:
            error_detail = {'0': 'Set application/json as Content-Type', '1': 'Provide json payload'}
            raise ApiError(code=400, title="No input data provided", detail=error_detail, source=endpoint)
        else:
            logger.debug("json_data: " + json.dumps(json_data))

        # Validate payload content
        schema = SettingsSchemaForUpdate()
        schema_validation_result = schema.load(json_data)

        # Check validation errors
        if schema_validation_result.errors:
            logger.error("Invalid payload")
            raise ApiError(code=400, title="Invalid payload", detail=dict(schema_validation_result.errors), source=endpoint)
        else:
            logger.debug("JSON validation -> OK")

        try:
            settings_id_from_payload = json_data['data'].get("id", "")
        except Exception as exp:
            error_title = "Could not get id from payload"
            logger.error(error_title)
            raise ApiError(
                code=404,
                title=error_title,
                detail=repr(exp),
                source=endpoint
            )

        # Check if emails_id from path and payload are matching
        if settings_id != settings_id_from_payload:
            error_title = "Email IDs from path and payload are not matching"
            compared_ids = {'IdFromPath': settings_id, 'IdFromPayload': settings_id_from_payload}
            logger.error(error_title + ", " + json.dumps(compared_ids))
            raise ApiError(
                code=403,
                title=error_title,
                detail=compared_ids,
                source=endpoint
            )
        else:
            logger.info("Setting IDs from path and payload are matching")

        # Collect data
        try:
            attributes = json_data['data']['attributes']
        except Exception as exp:
            error_title = "Could not collect data"
            logger.error(error_title)
            raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

        # Update Setting
        try:
            logger.info("Updating Setting")
            db_entries = update_setting(account_id=account_id, id=settings_id, attributes=attributes)
        except Exception as exp:
            # TODO: Error handling on more detailed level
            error_title = "No Setting found"
            logger.error(error_title)
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.info("Setting Updated")

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
    AccountParticulars,
    '/accounts/<string:account_id>/particulars',
    '/accounts/<string:account_id>/particulars/',
    endpoint='account-particulars'
)

account_api.add_resource(
    AccountParticular,
    '/accounts/<string:account_id>/particulars/<string:particulars_id>',
    '/accounts/<string:account_id>/particulars/<string:particulars_id>/',
    endpoint='account-particular'
)

account_api.add_resource(
    AccountContacts,
    '/accounts/<string:account_id>/contacts/',
    '/accounts/<string:account_id>/contacts',
    endpoint='account-contacts'
)

account_api.add_resource(
    AccountContact,
    '/accounts/<string:account_id>/contacts/<string:contacts_id>/',
    '/accounts/<string:account_id>/contacts/<string:contacts_id>',
    endpoint='account-contact'
)

account_api.add_resource(
    AccountEmails,
    '/accounts/<string:account_id>/emails/',
    '/accounts/<string:account_id>/emails',
    endpoint='account-emails'
)

account_api.add_resource(
    AccountEmail,
    '/accounts/<string:account_id>/emails/<string:emails_id>/',
    '/accounts/<string:account_id>/emails/<string:emails_id>',
    endpoint='account-email'
)

account_api.add_resource(
    AccountTelephones,
    '/accounts/<string:account_id>/telephones/',
    '/accounts/<string:account_id>/telephones',
    endpoint='account-telephones'
)

account_api.add_resource(
    AccountTelephone,
    '/accounts/<string:account_id>/telephones/<string:telephones_id>/',
    '/accounts/<string:account_id>/telephones/<string:telephones_id>',
    endpoint='account-telephone'
)

account_api.add_resource(
    AccountSettings,
    '/accounts/<string:account_id>/settings/',
    '/accounts/<string:account_id>/settings',
    endpoint='account-settings'
)

account_api.add_resource(
    AccountSetting,
    '/accounts/<string:account_id>/settings/<string:settings_id>/',
    '/accounts/<string:account_id>/settings/<string:settings_id>',
    endpoint='account-setting'
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



