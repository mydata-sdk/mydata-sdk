# -*- coding: utf-8 -*-

"""
Test Cases for External API

__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

import unittest
from base64 import b64encode
from random import randint

from flask import json
from app import create_app
from app.tests.controller import is_json, validate_json, account_create, default_headers, account_info_update, \
    generate_string, generate_sl_payload, generate_sl_init_source, generate_sl_init_sink, generate_sl_store_payload, \
    gen_jwk_key, generate_consent_status_payload, generate_consent_payload, generate_sls_store_payload
from app.tests.schemas.schema_account import schema_account_create, schema_account_auth, schema_account_get, \
    schema_account_info_listing, schema_account_info, schema_account_event_log_listing, schema_account_export
from app.tests.schemas.schema_authorisation import schema_consent_status_change, schema_give_consent, \
    schema_consent_listing, schema_consent, schema_consent_status_listing, schema_consent_status
from app.tests.schemas.schema_error import schema_request_error_detail_as_str, schema_request_error_detail_as_dict
from app.tests.schemas.schema_service_linking import schema_slr_listing, schema_slr_init, schema_slr_sign, \
    schema_slr_store, schema_slr_status, schema_slr, schema_slr_status_listing
from app.tests.schemas.schema_system import schema_db_clear, system_running, schema_sdk_auth


class UiTestCase(unittest.TestCase):

    API_PREFIX_INTERNAL = "/account/api/v1.3/internal"
    API_PREFIX_EXTERNAL = "/account/api/v1.3/external"

    SDK_USERNAME = "test_sdk"
    SDK_PASSWORD = "test_sdk_pw"

    # Operator info
    OPERATOR_ID = str(randint(100, 1000))
    OPERATOR_KEY_OBJECT, OPERATOR_KEY_PRIVATE_JSON, OPERATOR_KEY_PUBLIC_JSON, OPERATOR_KID = gen_jwk_key(prefix="operator")
    OPERATOR_KEY_PUBLIC = json.loads(OPERATOR_KEY_PUBLIC_JSON)
    OPERATOR_KEY_PRIVATE = json.loads(OPERATOR_KEY_PRIVATE_JSON)

    # Sink Service
    SINK_SERVICE_ID = "srv_sink-" + str(randint(100, 1000))
    SINK_SURROGATE_ID = "sink-surrogate-" + str(randint(100, 1000))
    SINK_KEY_OBJECT, SINK_KEY_PRIVATE_JSON, SINK_KEY_PUBLIC_JSON, SINK_KID = gen_jwk_key(prefix="srv_sink")
    SINK_KEY_PRIVATE = json.loads(SINK_KEY_PRIVATE_JSON)
    SINK_KEY_PUBLIC = json.loads(SINK_KEY_PUBLIC_JSON)

    # Source Service
    SOURCE_SERVICE_ID = "srv_source-" + str(randint(100, 1000))
    SOURCE_SURROGATE_ID = "source-surrogate-" + str(randint(100, 1000))
    SOURCE_KEY_OBJECT, SOURCE_KEY_PRIVATE_JSON, SOURCE_KEY_PUBLIC_JSON, SOURCE_KID = gen_jwk_key(prefix="srv_sink")
    SOURCE_KEY_PRIVATE = json.loads(SOURCE_KEY_PRIVATE_JSON)
    SOURCE_KEY_PUBLIC = json.loads(SOURCE_KEY_PUBLIC_JSON)

    def setUp(self):
        """
        TestCase Set Up
        :return:
        """
        app = create_app()
        app.config['TESTING'] = True
        app = app.test_client()
        self.app = app

    def tearDown(self):
        """
        TestCase Tear Down
        :return:
        """
        pass

    ##########
    ##########
    def test_system_running(self):
        """
        Test system running
        :return:
        """
        url = '/'

        response = self.app.get(url)
        unittest.TestCase.assertEqual(self, response.status_code, 200)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, system_running))

    ##########
    ##########
    def test_sdk_auth(self):
        """
        SDK authentication
        :return:
        """
        request_headers = default_headers
        request_headers['Authorization'] = 'Basic ' + b64encode("{0}:{1}".format(self.SDK_USERNAME, self.SDK_PASSWORD))

        url = self.API_PREFIX_INTERNAL + '/auth/sdk/'
        response = self.app.get(url, headers=request_headers)

        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_sdk_auth))

        response_json = json.loads(response.data)
        api_key = response_json["Api-Key-Sdk"]
        return api_key

    ##########
    ##########
    def test_system_routes(self):
        """
        Test system running
        :return:
        """
        url = '/system/routes/'

        response = self.app.get(url)
        unittest.TestCase.assertEqual(self, response.status_code, 200)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)

    ##########
    ##########
    def test_clear_db_positive(self):
        """
        Test database clearing
        :return:
        """
        response = self.app.get('/system/db/clear/')
        unittest.TestCase.assertEqual(self, response.status_code, 200)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_db_clear))

    ##########
    ##########
    def test_account_create_password_too_long(self):
        """
        Test Account creation. Password too long
        :return:
        """

        url = self.API_PREFIX_EXTERNAL + '/accounts/'
        account_json, username, password = account_create(password_length=21)
        response = self.app.post(url, data=account_json, headers=default_headers)

        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_account_create_password_too_short(self):
        """
        Test Account creation. Password too short
        :return:
        """

        account_json, username, password = account_create(password_length=3)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_account_create_username_too_long(self):
        """
        Test Account creation. Username too long
        :return:
        """

        account_json, username, password = account_create(username_length=256)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_account_create_username_too_short(self):
        """
        Test Account creation. Username too short
        :return:
        """

        account_json, username, password = account_create(username_length=2)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_account_create_firstname_too_long(self):
        """
        Test Account creation. First name too long
        :return:
        """

        account_json, username, password = account_create(firstname_length=256)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_account_create_firstname_too_short(self):
        """
        Test Account creation. First name too short
        :return:
        """

        account_json, username, password = account_create(firstname_length=2)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_account_create_lastname_too_long(self):
        """
        Test Account creation. Last name too long
        :return:
        """

        account_json, username, password = account_create(lastname_length=256)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_account_create_lastname_too_short(self):
        """
        Test Account creation. Last name too short
        :return:
        """

        account_json, username, password = account_create(lastname_length=2)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_account_create_positive(self):
        """
        Test Account creation. Positive case
        :return:
        """

        account_json, account_username, account_password = account_create()
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create))

        return account_username, account_password

    ##########
    ##########
    def test_account_create_username_exists(self):
        """
        Test Account creation. Username already exits
        :return:
        """

        account_username, account_password = self.test_account_create_positive()
        account_json, account_username, account_password = account_create(username=account_username)

        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 409, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_username, account_password

    ##########
    ##########
    def test_account_authentication(self):
        """
        Test user authentication
        :return:
        """

        account_username, account_password = self.test_account_create_positive()

        request_headers = default_headers
        request_headers['Authorization'] = 'Basic ' + b64encode("{0}:{1}".format(account_username, account_password))

        url = self.API_PREFIX_EXTERNAL + '/auth/user/'
        response = self.app.get(url, headers=request_headers)

        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_auth))

        response_json = json.loads(response.data)
        account_api_key = response_json["Api-Key-User"]
        account_id = response_json["account_id"]

        return account_api_key, account_id, account_username, account_password

    ##########
    ##########
    def test_account_fetch(self):
        """
        Fetch Account entry
        :return:
        """

        account_api_key, account_id, account_username, account_password = self.test_account_authentication()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_get))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_delete(self):
        """
        Test user deletion
        :return:
        """

        account_api_key, account_id, account_username, account_password = self.test_account_authentication()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/"

        response = self.app.delete(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 204, msg=response.data)

        return account_api_key, account_id, account_username, account_password

    ##########
    ##########
    def test_account_authentication_with_deleted_account(self):
        """
        Test user authentication
        :return:
        """

        account_api_key, account_id, account_username, account_password = self.test_account_delete()

        request_headers = default_headers
        request_headers['Authorization'] = 'Basic ' + b64encode("{0}:{1}".format(account_username, account_password))

        url = self.API_PREFIX_EXTERNAL + '/auth/user/'
        response = self.app.get(url, headers=request_headers)

        unittest.TestCase.assertEqual(self, response.status_code, 401, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_api_key, account_id, account_username, account_password

    ##########
    ##########
    def test_account_fetch_with_deleted_account(self):
        """
        Fetch Account entry
        :return:
        """

        account_api_key, account_id, account_username, account_password = self.test_account_delete()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 401, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_info_fetch_listing(self):
        """
        Fetch AccountInfo listing
        :return:
        """

        account_api_key, account_id, account_username, account_password = self.test_account_authentication()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/info/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_info_listing))
        account_info_id = json.loads(response.data)['data'][0]['id']

        return account_api_key, account_id, account_info_id

    ##########
    ##########
    def test_account_info_fetch_listing_wrong_account_id(self):
        """
        Fetch AccountInfo listing - Wrong account_id
        :return:
        """

        account_api_key, account_id, account_username, account_password = self.test_account_authentication()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(45864586) + "/info/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_info_fetch_one(self):
        """
        Fetch AccountInfo entry by ID
        :return:
        """

        account_api_key, account_id, account_info_id = self.test_account_info_fetch_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/info/" + str(account_info_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_info))
        account_avatar = json.loads(response.data)['data']['attributes']['avatar']

        return account_api_key, account_id, account_info_id, account_avatar

    ##########
    ##########
    def test_account_info_fetch_one_wrong_account_id(self):
        """
        Fetch AccountInfo entry by ID - Wrong ID
        :return:
        """

        account_api_key, account_id, account_info_id = self.test_account_info_fetch_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(456464984) + "/info/" + str(account_info_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_info_fetch_one_wrong_info_id(self):
        """
        Fetch AccountInfo entry by ID - Wrong ID
        :return:
        """

        account_api_key, account_id, account_info_id = self.test_account_info_fetch_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/info/" + str(account_api_key) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_info_update_all(self):
        """
        Update AccountInfo entry by ID
        :return:
        """

        account_api_key, account_id, account_info_id, account_avatar = self.test_account_info_fetch_one()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        payload = account_info_update(
            object_id=account_info_id,
            firstname=generate_string(n=10),
            lastname=generate_string(n=10),
            avatar=account_avatar
        )

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/info/" + str(account_info_id) + "/"

        response = self.app.patch(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_info))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_info_update_first_name(self):
        """
        Update AccountInfo entry by ID
        :return:
        """

        account_api_key, account_id, account_info_id, account_avatar = self.test_account_info_fetch_one()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        payload = account_info_update(object_id=account_info_id, firstname=generate_string(n=10))

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/info/" + str(account_info_id) + "/"

        response = self.app.patch(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_info))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_info_update_last_name(self):
        """
        Update AccountInfo entry by ID
        :return:
        """

        account_api_key, account_id, account_info_id, account_avatar = self.test_account_info_fetch_one()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        payload = account_info_update(object_id=account_info_id, lastname=generate_string(n=10))

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/info/" + str(account_info_id) + "/"

        response = self.app.patch(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_info))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_info_update_avatar(self):
        """
        Update AccountInfo entry by ID
        :return:
        """

        account_api_key, account_id, account_info_id, account_avatar = self.test_account_info_fetch_one()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        payload = account_info_update(object_id=account_info_id, avatar=account_avatar)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/info/" + str(account_info_id) + "/"

        response = self.app.patch(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_info))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_info_update_without_modifications(self):
        """
        Update AccountInfo entry by ID
        :return:
        """

        account_api_key, account_id, account_info_id, account_avatar = self.test_account_info_fetch_one()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        payload = account_info_update(object_id=account_info_id)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/info/" + str(account_info_id) + "/"

        response = self.app.patch(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_info))

        return account_api_key, account_id

    ##########
    ##########
    def test_account_info_update_with_wrong_id(self):
        """
        Update AccountInfo entry by ID
        :return:
        """

        account_api_key, account_id, account_info_id, account_avatar = self.test_account_info_fetch_one()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        payload = account_info_update()

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/info/" + str(account_info_id) + "/"

        response = self.app.patch(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_api_key, account_id

    #################################################################################
    #                                                                               #
    # Content Creation via INTERNAL API                                             #
    #                                                                               #
    #################################################################################

    ##########
    ##########
    def test_for_account_link_services(self):
        """
        Link two services for same Account
        :return: account_id, user_api_key, sdk_api_key, source_slr_id, sink_slr_id
        """

        # Create and Authenticate Account
        account_api_key, account_id, account_username, account_password = self.test_account_authentication()

        # Authenticate Operator-SDK
        sdk_api_key = self.test_sdk_auth()

        # Authentication for following requests
        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        request_headers['Api-Key-User'] = str(account_api_key)

        # Service Link Init for Source Service
        source_slr_init_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/source/"
        source_slr_init_payload, source_slr_code, source_slr_id = generate_sl_init_source()
        source_slr_init_response = self.app.post(source_slr_init_url, data=source_slr_init_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, source_slr_init_response.status_code, 201, msg=source_slr_init_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=source_slr_init_response.data), msg=source_slr_init_response.data)
        unittest.TestCase.assertTrue(self, validate_json(source_slr_init_response.data, schema_slr_init))

        # Service Link Init for Sink Service
        sink_slr_init_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/sink/"
        sink_slr_init_payload, sink_slr_code, sink_slr_id, sink_slr_pop_key = generate_sl_init_sink()
        sink_slr_init_response = self.app.post(sink_slr_init_url, data=sink_slr_init_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, sink_slr_init_response.status_code, 201, msg=sink_slr_init_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=sink_slr_init_response.data), msg=sink_slr_init_response.data)
        unittest.TestCase.assertTrue(self, validate_json(sink_slr_init_response.data, schema_slr_init))

        # Account Owner's signature for Service Link of Source Service
        source_slr_sign_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/"
        source_slr_sign_payload = generate_sl_payload(
                slr_id=source_slr_id,
                operator_id=self.OPERATOR_ID,
                operator_key=self.OPERATOR_KEY_PUBLIC,
                service_id=self.SOURCE_SERVICE_ID,
                surrogate_id=self.SOURCE_SURROGATE_ID
            )
        source_slr_sign_response = self.app.patch(source_slr_sign_url, data=source_slr_sign_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, source_slr_sign_response.status_code, 201, msg=source_slr_sign_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=source_slr_sign_response.data), msg=source_slr_sign_response.data)
        unittest.TestCase.assertTrue(self, validate_json(source_slr_sign_response.data, schema_slr_sign))

        # Account Owner's signature for Service Link of Sink Service
        sink_slr_sign_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(sink_slr_id) + "/"
        sink_slr_sign_payload = generate_sl_payload(
                slr_id=sink_slr_id,
                operator_id=self.OPERATOR_ID,
                operator_key=self.OPERATOR_KEY_PUBLIC,
                service_id=self.SINK_SERVICE_ID,
                surrogate_id=self.SINK_SURROGATE_ID
            )
        sink_slr_sign_response = self.app.patch(sink_slr_sign_url, data=sink_slr_sign_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, sink_slr_sign_response.status_code, 201, msg=sink_slr_sign_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=sink_slr_sign_response.data), msg=sink_slr_sign_response.data)
        unittest.TestCase.assertTrue(self, validate_json(sink_slr_sign_response.data, schema_slr_sign))

        # Store Service Link of Source Service
        source_slr_store_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + source_slr_id + "/store/"
        source_slr_store_payload = generate_sl_store_payload(
            slr_id=source_slr_id,
            slr_signed=json.loads(source_slr_sign_response.data)['data'],
            surrogate_id=self.SOURCE_SURROGATE_ID,
            service_key=self.SOURCE_KEY_OBJECT,
            service_kid=self.SOURCE_KID
        )
        source_slr_store_response = self.app.post(source_slr_store_url, data=source_slr_store_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, source_slr_store_response.status_code, 201, msg=source_slr_store_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=source_slr_store_response.data), msg=source_slr_store_response.data)
        unittest.TestCase.assertTrue(self, validate_json(source_slr_store_response.data, schema_slr_store))
        source_ssr_id = json.loads(source_slr_store_response.data)['data']['ssr']['id']

        # Store Service Link of Sink Service
        sink_slr_store_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + sink_slr_id + "/store/"
        sink_slr_store_payload = generate_sl_store_payload(
            slr_id=sink_slr_id,
            slr_signed=json.loads(sink_slr_sign_response.data)['data'],
            surrogate_id=self.SINK_SURROGATE_ID,
            service_key=self.SINK_KEY_OBJECT,
            service_kid=self.SINK_KID
        )
        sink_slr_store_response = self.app.post(sink_slr_store_url, data=sink_slr_store_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, sink_slr_store_response.status_code, 201, msg=sink_slr_store_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=sink_slr_store_response.data), msg=sink_slr_store_response.data)
        unittest.TestCase.assertTrue(self, validate_json(sink_slr_store_response.data, schema_slr_store))
        sink_ssr_id = json.loads(sink_slr_store_response.data)['data']['ssr']['id']

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id

    ##########
    ##########
    def test_for_account_change_slr_status_source(self):
        """
        Test Source SLR status change
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + source_slr_id + "/statuses/"
        payload = generate_sls_store_payload(
            slr_id=source_slr_id,
            surrogate_id=self.SOURCE_SURROGATE_ID,
            prev_record_id=source_ssr_id,
            status="Removed"
        )

        source_ssr_id_new = json.loads(payload)['data']['attributes']['record_id']

        response = self.app.post(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id

    ##########
    ##########
    def test_for_account_change_slr_status_sink(self):
        """
        Test Sink SLR status change
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id = self.test_for_account_change_slr_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + sink_slr_id + "/statuses/"
        payload = generate_sls_store_payload(
            slr_id=sink_slr_id,
            surrogate_id=self.SINK_SURROGATE_ID,
            prev_record_id=sink_ssr_id,
            status="Removed"
        )

        sink_ssr_id_new = json.loads(payload)['data']['attributes']['record_id']

        response = self.app.post(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new

    ##########
    ##########
    def test_for_account_give_consent_multiple(self):
        """
        Give Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        # Give Consent
        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new = self.test_for_account_change_slr_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        count = 0
        source_cr_id_array = []
        source_csr_id_array = []
        sink_cr_id_array = []
        sink_csr_id_array = []
        for i in range(0, 3):
            count += 1
            give_consent_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + source_slr_id + "/" + sink_slr_id + "/consents/"
            give_consent_payload, source_cr_id, source_csr_id, sink_cr_id, sink_csr_id = generate_consent_payload(
                    source_surrogate_id=self.SOURCE_SURROGATE_ID,
                    source_slr_id=source_slr_id,
                    operator_id=self.OPERATOR_ID,
                    source_subject_id=self.SOURCE_SERVICE_ID,
                    sink_pop_key=self.SINK_KEY_PUBLIC,
                    operator_pub_key=self.OPERATOR_KEY_PUBLIC,
                    sink_surrogate_id=self.SINK_SURROGATE_ID,
                    sink_slr_id=sink_slr_id,
                    sink_subject_id=self.SINK_SERVICE_ID,
                    misformatted_payload=False
            )

            give_consent_response = self.app.post(give_consent_url, data=give_consent_payload, headers=request_headers)
            unittest.TestCase.assertEqual(self, give_consent_response.status_code, 201, msg=give_consent_response.data)
            unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
            unittest.TestCase.assertTrue(self, validate_json(give_consent_response.data, schema_give_consent))

            source_cr_id_array.append(source_cr_id)
            source_csr_id_array.append(source_csr_id)
            sink_cr_id_array.append(sink_cr_id)
            sink_csr_id_array.append(sink_csr_id)

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_for_account_change_consent_status_source(self):
        """
        Change Consent Status - Source Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        source_cr_id = source_cr_id_array[0]
        source_csr_id = source_csr_id_array[0]

        # Change Consent Status of Source Service
        consent_status_change_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + source_cr_id + "/statuses/"
        consent_status_change_payload, source_csr_id_new = generate_consent_status_payload(
            surrogate_id=self.SOURCE_SURROGATE_ID,
            cr_id=source_cr_id,
            consent_status="Paused",
            prev_record_id=source_csr_id,
            misformatted_payload=False,
            cr_id_fault=False
        )

        consent_status_change_response = self.app.post(consent_status_change_url, data=consent_status_change_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 201, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_consent_status_change))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_for_account_change_consent_status_sink(self):
        """
        Change Consent Status - Sink Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id, sink_csr_id_new
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        sink_cr_id = sink_cr_id_array[0]
        sink_csr_id = sink_csr_id_array[0]

        # Change Consent Status of Source Service
        consent_status_change_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + sink_cr_id + "/statuses/"
        consent_status_change_payload, sink_csr_id_new = generate_consent_status_payload(
            surrogate_id=self.SINK_SURROGATE_ID,
            cr_id=sink_cr_id,
            consent_status="Paused",
            prev_record_id=sink_csr_id,
            misformatted_payload=False,
            cr_id_fault=False
        )

        consent_status_change_response = self.app.post(consent_status_change_url, data=consent_status_change_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 201, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_consent_status_change))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    # Service Links - Positive case
    ##########
    ##########
    def test_fetch_slr_listing(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_listing))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_one(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_statuses(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status_listing))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_status(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/statuses/" + str(source_ssr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_status_last(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    # Service Links - Negative cases
    ##########
    ##########
    def test_fetch_slr_listing_wrong_account_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_slr_id) + "/servicelinks/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_one_wrong_account_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_slr_id) + "/servicelinks/" + str(source_slr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_one_wrong_slr_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_statuses_wrong_account_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_slr_id) + "/servicelinks/" + str(source_slr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_statuses_wrong_slr_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_status_wrong_account_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_slr_id) + "/servicelinks/" + str(source_slr_id) + "/statuses/" + str(source_ssr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_status_wrong_slr_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/statuses/" + str(source_ssr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_status_wrong_slsr_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/statuses/" + str(sink_ssr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_status_last_wrong_account_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_ssr_id) + "/servicelinks/" + str(source_slr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_slr_status_last_wrong_slr_id(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    # Consents - Positive case
    ##########
    ##########
    def test_fetch_consent_listing(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_one(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_last(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/last/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_listing(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status_listing))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_listing_filtered(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/statuses/?status_id=" + str(source_csr_id_array[0])

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status_listing))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_one(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/statuses/" + str(source_csr_id_array[0]) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    # Consents - Negative cases
    ##########
    ##########
    def test_fetch_consent_listing_wrong_account_id(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_ssr_id) + "/servicelinks/" + str(source_slr_id) + "/consents/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_listing_wrong_slr_id(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/consents/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_one_wrong_account_id(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_slr_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_one_wrong_slr_id(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/consents/" + str(source_cr_id_array[0]) + "/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_one_wrong_cr_id(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(sink_cr_id_array[0]) + "/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_last_wrong_account_id(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_ssr_id) + "/servicelinks/" + str(source_slr_id) + "/consents/last/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_last_wrong_slr_id(self):
        """
        Test Fetch Consent for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/consents/last/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_listing_wrong_account_id(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_slr_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_listing_wrong_slr_id(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(sink_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_listing_wrong_cr_id(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(sink_cr_id_array[0]) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_one_wrong_account_id(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(source_ssr_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/statuses/" + str(source_csr_id_array[0]) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_one_wrong_slr_id(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(sink_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/statuses/" + str(source_csr_id_array[0]) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_one_wrong_cr_id(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(sink_cr_id_array[0]) + "/statuses/" + str(source_csr_id_array[0]) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_consent_status_one_wrong_csr_id(self):
        """
        Test Fetch Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/statuses/" + str(sink_csr_id_array[0]) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_event_log_listing(self):
        """
        Test Fetch EventLog listing
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_for_account_change_consent_status_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/logs/events/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_event_log_listing))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array

    ##########
    ##########
    def test_fetch_export(self):
        """
        Test Fetch Account Export
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array = self.test_fetch_event_log_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/export/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_export))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_ssr_id_new, sink_slr_id, sink_ssr_id, sink_ssr_id_new, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array



    ##########
    ##########


if __name__ == '__main__':
    unittest.main()
