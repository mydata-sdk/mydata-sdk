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

from flask import json

from app import create_app
from app.tests.controller import is_json, validate_json, account_create, default_headers, generate_string, \
    print_test_title, generate_sl_init_sink
from app.tests.schemas.schema_account import schema_account_create, schema_account_create_password_length, \
    schema_account_create_username_length, schema_account_create_email_length, schema_account_create_email_invalid, \
    schema_account_create_firstname_length, schema_account_create_lastname_length, schema_account_create_date_invalid, \
    schema_account_create_tos, schema_account_auth, schema_account_get
from app.tests.schemas.schema_service_linking import schema_slr_init
from app.tests.schemas.schema_system import schema_db_clear, system_running, schema_sdk_auth


class SdkTestCase(unittest.TestCase):

    API_PREFIX_INTERNAL = "/account/api/v1.3/internal"
    API_PREFIX_EXTERNAL = "/account/api/v1.3/external"
    SDK_USERNAME = "test_sdk"
    SDK_PASSWORD = "test_sdk_pw"

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
        # TODO: Uncomment following line
        #self.test_clear_db_positive()

    ##########
    ##########
    def test_system_running(self):
        """
        Test system running
        :return:
        """
        print_test_title(test_name="test_system_running")
        url = self.API_PREFIX_INTERNAL + '/system/status/'

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
        url = self.API_PREFIX_INTERNAL + '/system/routes/'

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
        response = self.app.get(self.API_PREFIX_INTERNAL + '/system/db/clear/')
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

    # TODO: Test Account authentication with deleted Account
    # TODO: Test Resource fetching with removed Account

    ##########
    ##########
    def test_slr_init_sink(self):
        """
        Test user deletion
        :return:
        """
        print_test_title(test_name="test_slr_init_source")

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/sink/"

        payload, code, slr_id, pop_key = generate_sl_init_sink()

        response = self.app.post(url, data=payload, headers=request_headers)
        print("status_code: " + str(response.status_code))
        print("response.data: " + json.dumps(json.loads(response.data), indent=4))
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        # unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        # unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_init))

if __name__ == '__main__':
    unittest.main()



