# -*- coding: utf-8 -*-

"""
Minimum viable account - API Auth module

__author__ = "Jani Yli-Kantola"
__copyright__ = "Digital Health Revolution (c) 2016"
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
__date__ = 26.5.2016
"""

from flask import Blueprint, make_response, request
from flask_restful import Resource, Api

from app.helpers import get_custom_logger, make_json_response, ApiError
from app.mod_account.controllers import verify_account_id_match
from app.mod_api_auth.controllers import get_account_api_key, get_api_key_sdk, get_user_api_key, get_sdk_api_key, \
    requires_api_auth_sdk, requires_api_auth_user
from app.mod_api_auth.helpers import ApiKeyNotFoundError
from app.mod_auth.helpers import get_account_id_by_username_and_password

logger = get_custom_logger(__name__)

# Define the blueprint: 'auth', set its url prefix: app.url/auth
mod_api_auth = Blueprint('api_auth', __name__, template_folder='templates')
api = Api(mod_api_auth)


class ApiKeyUser(Resource):
    account_id = None
    username = None
    api_key = None

    def check_basic_auth(self, username, password):
        """
        This function is called to check if a username password combination is valid.
        """
        logger.info("Checking username and password")
        user = get_account_id_by_username_and_password(username=username, password=password)
        logger.debug("User with following info: " + str(user))
        if user is not None:
            self.account_id = user['account_id']
            self.username = user['username']
            logger.info("User authenticated")
            return True
        else:
            logger.info("User not authenticated")
            return False

    @staticmethod
    def authenticate():
        """Sends a 401 response that can be used to enable authentication"""
        logger.info("Unauthorized - Authentication required")
        raise ApiError(code=401, title="Unauthorized", detail="Could not verify your access level")

    def get(self):
        try:
            endpoint = str(api.url_for(self))
        except Exception as exp:
            endpoint = str(__name__)

        logger.info("Authenticating user")

        auth = request.authorization
        if not auth or not self.check_basic_auth(auth.username, auth.password):
            return self.authenticate()
        else:
            logger.info("Authenticated")

        try:
            api_key = get_account_api_key(account_id=self.account_id)
        except ApiKeyNotFoundError as exp:
            error_title = "ApiKey not found for authenticated user"
            logger.error(error_title)
            logger.error(repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        except Exception as exp:
            error_title = "Could not get ApiKey for authenticated user"
            logger.error(error_title)
            logger.error(repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("account_id: " + str(self.account_id))
            logger.debug("api_key: " + str(api_key))

        response_data = {
            'Api-Key-User': api_key,
            'account_id': str(self.account_id)
        }

        return make_json_response(data=response_data, status_code=200)


class ApiKeySDK(Resource):
    username = "test_sdk"
    password = "test_sdk_pw"
    api_key = None

    def check_basic_auth(self, username, password):
        """
        This function is called to check if a username password combination is valid.
        """
        logger.debug("Provided username: " + str(username))
        logger.debug("Provided password: " + str(password))

        if (username == self.username) and (password == self.password):
            return True
        else:
            return False

    @staticmethod
    def authenticate():
        """Sends a 401 response that enables basic auth"""
        headers = {'WWW-Authenticate': 'Basic realm="Login Required"'}
        body = 'Could not verify your access level for that URL. \n You have to login with proper credentials'
        return make_response(body, 401, headers)

    def get(self):
        # account_id = session['user_id']
        # logger.debug('Account id: ' + account_id)

        auth = request.authorization
        if not auth or not self.check_basic_auth(auth.username, auth.password):
            return self.authenticate()

        api_key_sdk = get_api_key_sdk()
        logger.debug("api_key_sdk: " + api_key_sdk)

        response_data = {
            'Api-Key-Sdk': api_key_sdk
        }

        return make_json_response(data=response_data, status_code=200)


class AccountInfo(Resource):
    @requires_api_auth_user
    @requires_api_auth_sdk
    def get(self, account_id):
        """
        Verify that API Key belongs to specified user

        :param account_id:
        :param slr_id:
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

        # Response data container
        try:
            response_data = {
              "data": {
                "type": "Account",
                "id": account_id,
                "attributes": {}
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
        return make_json_response(data=response_data_dict, status_code=200)


# Register resources
api.add_resource(ApiKeyUser, '/external/auth/user/', endpoint='api_auth_user')
api.add_resource(ApiKeySDK, '/internal/auth/sdk/', endpoint='api_auth_sdk')
api.add_resource(AccountInfo, '/internal/auth/sdk/account/<string:account_id>/info/', endpoint='api_auth_account_info')
