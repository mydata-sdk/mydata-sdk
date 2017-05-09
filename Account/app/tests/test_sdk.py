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

import unittest
from base64 import b64encode
from random import randint

from flask import json

from app import create_app
from app.tests.controller import is_json, validate_json, account_create, default_headers, \
    print_test_title, generate_sl_init_sink, generate_sl_init_source, gen_jwk_key, generate_sl_payload, \
    generate_sl_store_payload, generate_sls_store_payload, generate_signed_ssr_store_payload
from app.tests.schemas.schema_account import schema_account_create, schema_account_create_password_length, \
    schema_account_create_username_length, schema_account_create_email_length, schema_account_create_email_invalid, \
    schema_account_create_firstname_length, schema_account_create_lastname_length, schema_account_create_date_invalid, \
    schema_account_create_tos, schema_account_auth, schema_account_get, schema_account_sdk_info
from app.tests.schemas.schema_error import schema_request_error_detail_as_str, schema_request_error_detail_as_dict
from app.tests.schemas.schema_service_linking import schema_slr_init, schema_slr_sign, \
    schema_slr_store, schema_slr_listing, schema_slr, schema_slr_status_listing, schema_slr_status
from app.tests.schemas.schema_system import schema_db_clear, system_running, schema_sdk_auth


class SdkTestCase(unittest.TestCase):

    API_PREFIX_INTERNAL = "/account/api/v1.3/internal"
    API_PREFIX_EXTERNAL = "/account/api/v1.3/external"
    SDK_USERNAME = "test_sdk"
    SDK_PASSWORD = "test_sdk_pw"

    # Operator info
    OPERATOR_ID = str(randint(100, 1000))
    OPERATOR_KEY_OBJECT, OPERATOR_KEY_JSON, OPERATOR_KID = gen_jwk_key(prefix="operator")
    OPERATOR_KEY = json.loads(OPERATOR_KEY_JSON)

    # Sink Service
    SINK_SERVICE_ID = "srv_sink-" + str(randint(100, 1000))
    SINK_SURROGATE_ID = "sink-surrogate-" + str(randint(100, 1000))
    SINK_KEY_OBJECT, SINK_KEY_JSON, SINK_KID = gen_jwk_key(prefix="srv_sink")
    SINK_KEY = json.loads(SINK_KEY_JSON)

    # Source Service
    SOURCE_SERVICE_ID = "srv_source-" + str(randint(100, 1000))
    SOURCE_SURROGATE_ID = "source-surrogate-" + str(randint(100, 1000))
    SOURCE_KEY_OBJECT, SOURCE_KEY_JSON, SOURCE_KID = gen_jwk_key(prefix="srv_sink")
    SOURCE_KEY = json.loads(SOURCE_KEY_JSON)

    def setUp(self):
        """
        TestCase Set Up
        :return:
        """
        app = create_app()
        app.config['TESTING'] = True
        app = app.test_client()
        self.app = app
        print("############################")

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
        print_test_title(test_name="test_system_running")
        url = '/system/status/'

        response = self.app.get(url)
        unittest.TestCase.assertEqual(self, response.status_code, 200)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, system_running))

    ##########
    ##########
    def test_system_routes(self):
        """
        Test system running
        :return:
        """
        print_test_title(test_name="test_system_routes")
        url = '/system/routes/'

        response = self.app.get(url)
        unittest.TestCase.assertEqual(self, response.status_code, 200)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        print(json.dumps(json.loads(response.data), indent=2))

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
    def test_clear_db_positive(self):
        """
        Test database clearing
        :return:
        """
        print_test_title(test_name="test_clear_db_positive")
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
        print_test_title(test_name="test_account_create_password_too_long")

        url = self.API_PREFIX_EXTERNAL + '/accounts/'
        account_json, username, password = account_create(password_length=21)
        response = self.app.post(url, data=account_json, headers=default_headers)

        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_password_length))

    def test_account_create_password_too_short(self):
        """
        Test Account creation. Password too short
        :return:
        """
        print_test_title(test_name="test_account_create_password_too_short")

        account_json, username, password = account_create(password_length=3)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_password_length))

    ##########
    ##########
    def test_account_create_username_too_long(self):
        """
        Test Account creation. Username too long
        :return:
        """
        print_test_title(test_name="test_account_create_username_too_long")

        account_json, username, password = account_create(username_length=256)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_username_length))

    def test_account_create_username_too_short(self):
        """
        Test Account creation. Username too short
        :return:
        """
        print_test_title(test_name="test_account_create_username_too_short")

        account_json, username, password = account_create(username_length=2)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_username_length))

    ##########
    ##########
    def test_account_create_email_too_long(self):
        """
        Test Account creation. Email too long
        :return:
        """
        print_test_title(test_name="test_account_create_email_too_long")

        account_json, username, password = account_create(email_length=256)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_email_length))

    def test_account_create_email_invalid(self):
        """
        Test Account creation. Email invalid
        :return:
        """
        print_test_title(test_name="test_account_create_email_invalid")

        account_json, username, password = account_create(invalid_email=True)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_email_invalid))

    ##########
    ##########
    def test_account_create_firstname_too_long(self):
        """
        Test Account creation. First name too long
        :return:
        """
        print_test_title(test_name="test_account_create_firstname_too_long")

        account_json, username, password = account_create(firstname_length=256)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_firstname_length))

    def test_account_create_firstname_too_short(self):
        """
        Test Account creation. First name too short
        :return:
        """
        print_test_title(test_name="test_account_create_firstname_too_short")

        account_json, username, password = account_create(firstname_length=2)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_firstname_length))

    ##########
    ##########
    def test_account_create_lastname_too_long(self):
        """
        Test Account creation. Last name too long
        :return:
        """
        print_test_title(test_name="test_account_create_lastname_too_long")

        account_json, username, password = account_create(lastname_length=256)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_lastname_length))

    def test_account_create_lastname_too_short(self):
        """
        Test Account creation. Last name too short
        :return:
        """
        print_test_title(test_name="test_account_create_lastname_too_short")

        account_json, username, password = account_create(lastname_length=2)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_lastname_length))

    ##########
    ##########
    def test_account_create_date_invalid(self):
        """
        Test Account creation. Date invalid
        :return:
        """
        print_test_title(test_name="test_account_create_date_invalid")

        account_json, username, password = account_create(invalid_date=True)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_date_invalid))

    ##########
    ##########
    def test_account_create_tos(self):
        """
        Test Account creation. acceptTermsOfService == False
        :return:
        """
        print_test_title(test_name="test_account_create_tos")

        account_json, username, password = account_create(accept_terms=False)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_tos))

    ##########
    ##########
    def test_account_create_positive(self):
        """
        Test Account creation. Positive case
        :return:
        """
        print_test_title(test_name="test_account_create_positive")

        account_json, account_username, account_password = account_create()
        print(account_json)
        response = self.app.post(self.API_PREFIX_EXTERNAL + '/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create))

        return account_username, account_password

    ##########
    ##########
    def test_account_authentication(self):
        """
        Test user authentication
        :return:
        """
        print_test_title(test_name="test_account_authentication")

        account_username, account_password = self.test_account_create_positive()
        # print("Using username: " + account_username)
        # print("Using password: " + account_password)

        request_headers = default_headers
        request_headers['Authorization'] = 'Basic ' + b64encode("{0}:{1}".format(account_username, account_password))
        # print (repr(request_headers))

        url = self.API_PREFIX_EXTERNAL + '/auth/user/'
        response = self.app.get(url, headers=request_headers)

        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_auth))

        response_json = json.loads(response.data)
        api_key = response_json["Api-Key-User"]
        account_id = response_json["account_id"]
        return api_key, account_id

    ##########
    ##########
    def test_account_fetch(self):
        """
        Fetch Account entry
        :return:
        """
        print_test_title(test_name="test_account_fetch")

        account_api_key, account_id = self.test_account_authentication()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_get))

    ##########
    ##########
    def test_account_delete(self):
        """
        Test user deletion
        :return:
        """
        print_test_title(test_name="test_account_delete")

        account_api_key, account_id = self.test_account_authentication()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)

        url = self.API_PREFIX_EXTERNAL + "/accounts/" + str(account_id) + "/"

        response = self.app.delete(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 204, msg=response.data)

    ##########
    ##########
    def test_sdk_account_info(self):
        """
        Verify User-API-Key belongs to specified user
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_sdk_account_info")

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/auth/sdk/account/" + str(account_id) + "/info/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_sdk_info))

        return account_id, account_api_key, sdk_api_key

    ##########
    ##########
    def test_slr_init_sink(self):
        """
        Test Sink SLR init
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_slr_init_sink")

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/sink/"

        payload, code, slr_id, pop_key = generate_sl_init_sink()

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_init))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_slr_init_sink_misformatted(self):
        """
        Test Sink SLR init with misformatted pop_key
        :return:
        """
        print_test_title(test_name="test_slr_init_sink_misformatted")

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/sink/"

        payload, code, slr_id, pop_key = generate_sl_init_sink(misformatted_payload=True)

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_slr_init_sink_duplicate(self):
        """
        Test Sink SLR init duplicate
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_slr_init_sink_duplicate")

        account_id, account_api_key, sdk_api_key, slr_id_original = self.test_slr_init_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/sink/"
        payload, code, slr_id, pop_key = generate_sl_init_sink(slr_id=slr_id_original)

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 409, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_slr_init_source(self):
        """
        Test Sink SLR init
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_slr_init_source")

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/source/"

        payload, code, slr_id = generate_sl_init_source()

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_init))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_slr_init_source_misformatted(self):
        """
        Test Source SLR init with misformatted pop_key
        :return:
        """
        print_test_title(test_name="test_slr_init_source_misformatted")

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/source/"

        payload, code, slr_id = generate_sl_init_source(misformatted_payload=True)

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_slr_init_source_duplicate(self):
        """
        Test Source SLR init duplicate
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_slr_init_source_duplicate")

        account_id, account_api_key, sdk_api_key, slr_id_original = self.test_slr_init_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/source/"
        payload, code, slr_id = generate_sl_init_source(slr_id=slr_id_original)

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 409, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_slr_sign_sink(self):
        """
        Test Sink SLR signing
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_sign_sink")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY,
            service_id=self.SINK_SERVICE_ID,
            surrogate_id=self.SINK_SURROGATE_ID
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_sign))

        return account_id, account_api_key, sdk_api_key, slr_id, response.data

    ##########
    ##########
    def test_slr_sign_sink_malformed(self):
        """
        Test Sink malformed SLR signing
        :return:
        """
        print_test_title(test_name="test_slr_sign_sink_malformed")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY,
            service_id=self.SINK_SERVICE_ID,
            surrogate_id=self.SINK_SURROGATE_ID,
            misformatted_payload=True
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_slr_sign_sink_wrong_id(self):
        """
        Test Sink SLR signing with wrong SLR id
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_sign_sink_wrong_id")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_sink()
        slr_id = "wrong-" + slr_id

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY,
            service_id=self.SINK_SERVICE_ID,
            surrogate_id=self.SINK_SURROGATE_ID
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id, response.data

    ##########
    ##########
    def test_slr_store_sink(self):
        """
        Test Sink SLR storing
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_store_sink")

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_sink()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SINK_SURROGATE_ID,
            service_key=self.SINK_KEY_OBJECT,
            service_kid=self.SINK_KID
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_store))

        return account_id, account_api_key, sdk_api_key, slr_id, response.data

    ##########
    ##########
    def test_slr_store_sink_malformed(self):
        """
        Test Sink SLR storing - Malformed
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_store_sink_malformed")

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_sink()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SINK_SURROGATE_ID,
            service_key=self.SINK_KEY_OBJECT,
            service_kid=self.SINK_KID,
            misformatted_payload=True
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

        return account_id, account_api_key, sdk_api_key, slr_id, response.data

    ##########
    ##########
    def test_slr_store_sink_malformed_signature(self):
        """
        Test Sink SLR storing - Signature verification fails
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_store_sink_malformed_signature")

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_sink()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SINK_SURROGATE_ID,
            service_key=self.SINK_KEY_OBJECT,
            service_kid=self.SINK_KID,
            misformatted_signature=True
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_slr_sign_source(self):
        """
        Test Source SLR signing
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_sign_source")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY,
            service_id=self.SOURCE_SERVICE_ID,
            surrogate_id=self.SOURCE_SURROGATE_ID
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_sign))

        return account_id, account_api_key, sdk_api_key, slr_id, response.data

    ##########
    ##########
    def test_slr_sign_source_malformed(self):
        """
        Test Source malformed SLR signing
        :return:
        """
        print_test_title(test_name="test_slr_sign_source_malformed")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY,
            service_id=self.SOURCE_SERVICE_ID,
            surrogate_id=self.SOURCE_SURROGATE_ID,
            misformatted_payload=True
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

    ##########
    ##########
    def test_slr_sign_source_wrong_id(self):
        """
        Test Source SLR signing with wrong SLR id
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_sign_source_wrong_id")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_source()
        slr_id = "wrong-" + slr_id

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY,
            service_id=self.SOURCE_SERVICE_ID,
            surrogate_id=self.SOURCE_SURROGATE_ID
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id, response.data

    ##########
    ##########
    def test_slr_store_source(self):
        """
        Test Source SLR storing
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_store_source")

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_source()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SOURCE_SURROGATE_ID,
            service_key=self.SOURCE_KEY_OBJECT,
            service_kid=self.SOURCE_KID
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_store))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_slr_store_source_malformed(self):
        """
        Test Source SLR storing - Malformed
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_store_source_malformed")

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_source()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SOURCE_SURROGATE_ID,
            service_key=self.SOURCE_KEY_OBJECT,
            service_kid=self.SOURCE_KID,
            misformatted_payload=True
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_slr_store_source_malformed_signature(self):
        """
        Test Source SLR storing - Signature verification fails
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_store_source_malformed_signature")

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_source()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SOURCE_SURROGATE_ID,
            service_key=self.SOURCE_KEY_OBJECT,
            service_kid=self.SOURCE_KID,
            misformatted_signature=True
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_slr_store_wrong_id(self):
        """
        Test SLR storing with wrong ID
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slr_store_wrong_id")

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_source()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SINK_SURROGATE_ID,
            service_key=self.SOURCE_KEY_OBJECT,
            service_kid=self.SOURCE_KID
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing(self):
        """
        Test Fetch SLR listing
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_listing")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_listing))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr(self):
        """
        Test Fetch SLR
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_wrong_id(self):
        """
        Test Fetch SLR with wrong slr id
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_wrong_id")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slr_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id_wrong) + "/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_status_listing(self):
        """
        Test Fetch SLR status listing
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_status_listing")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status_listing))
        response_data_dict = json.loads(response.data)
        slsr_id = response_data_dict['data'][0]['id']
        return account_id, account_api_key, sdk_api_key, slr_id, slsr_id

    ##########
    ##########
    def test_fetch_slr_status_listing_wrong_id(self):
        """
        Test Fetch SLR status listing with wrong slr_id
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_status_listing_wrong_id")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slr_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id_wrong) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_status(self):
        """
        Test Fetch SLR status by ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_status")

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_status_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/statuses/" + str(slsr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))

        return account_id, account_api_key, sdk_api_key, slr_id, slsr_id

    ##########
    ##########
    def test_fetch_slr_status_wrong_id(self):
        """
        Test Fetch SLR status by wrong ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_status_wrong_id")

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_status_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slrs_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/statuses/" + str(slrs_id_wrong) + "/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id, slsr_id

    ##########
    ##########
    def test_fetch_slr_last_status(self):
        """
        Test Fetch SLR last status
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_last_status")

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_status_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))
        response_data_dict = json.loads(response.data)
        slsr_id_from_response = response_data_dict['data']['id']

        return account_id, account_api_key, sdk_api_key, slr_id, slsr_id_from_response

    ##########
    ##########
    def test_fetch_slr_last_status_wrong_id(self):
        """
        Test Fetch SLR last status with wrong slr id
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_last_status_wrong_id")

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_status_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slr_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id_wrong) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id, slsr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service(self):
        """
        Test Fetch SLR listing for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_listing_for_service")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_listing))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_with_account_id(self):
        """
        Test Fetch SLR listing for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_listing_for_service_with_account_id")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/?account_id=" + str(account_id)

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_listing))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_wrong_id(self):
        """
        Test Fetch SLR listing for Service with wrong ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_listing_for_Service")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        service_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/services/" + service_id_wrong + "/servicelinks/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_for_service(self):
        """
        Test Fetch SLR for Service
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_for_Service")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(slr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_for_service_wrong_service_id(self):
        """
        Test Fetch SLR for Service with wrong Service ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_for_service_wrong_service_id")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        service_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/services/" + service_id_wrong + "/servicelinks/" + str(slr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_for_service_wrong_link_id(self):
        """
        Test Fetch SLR for Service with wrong Link ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """
        print_test_title(test_name="test_fetch_slr_for_service_wrong_link_id")

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slr_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(slr_id_wrong) + "/"

        response = self.app.get(url, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_ssr_store_source(self):
        """
        Test Source SSR storing
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slsr_store_source")

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_last_status()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/statuses/"
        payload = generate_sls_store_payload(
            slr_id=slr_id,
            surrogate_id=self.SOURCE_SURROGATE_ID,
            prev_record_id=slsr_id,
            status="Removed"
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_ssr_store_source_malformed(self):
        """
        Test Source SSR storing with malformed payload
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_ssr_store_source_malformed")

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_last_status()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/statuses/"
        payload = generate_sls_store_payload(
            slr_id=slr_id,
            surrogate_id=self.SOURCE_SURROGATE_ID,
            prev_record_id=slsr_id,
            status="Removed",
            misformatted_payload=True
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_ssr_store_source_signed(self):
        """
        Test Source SSR storing with signed SSR
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_slsr_store_source_signed")

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_last_status()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/statuses/signed/"
        payload = generate_signed_ssr_store_payload(
            slr_id=slr_id,
            surrogate_id=self.SOURCE_SURROGATE_ID,
            prev_record_id=slsr_id,
            status="Removed",
            operator_kid=self.OPERATOR_KID,
            operator_key=self.OPERATOR_KEY_OBJECT
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_ssr_store_source_signed_malformed(self):
        """
        Test Source SSR storing with signed SSR with malformed payload
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """
        print_test_title(test_name="test_ssr_store_source_signed_malformed")

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_last_status()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/statuses/signed/"
        payload = generate_signed_ssr_store_payload(
            slr_id=slr_id,
            surrogate_id=self.SOURCE_SURROGATE_ID,
            prev_record_id=slsr_id,
            status="Removed",
            operator_kid=self.OPERATOR_KID,
            operator_key=self.OPERATOR_KEY_OBJECT,
            misformatted_payload=True
        )
        print("payload: " + json.dumps(json.loads(payload), indent=4))

        response = self.app.post(url, data=payload, headers=request_headers)
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    # TODO: Test Account authentication with deleted Account
    # TODO: Test Resource fetching with removed Account


if __name__ == '__main__':
    unittest.main()
