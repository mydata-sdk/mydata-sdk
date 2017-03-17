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

from app import create_app
from app.tests.controller import is_json, validate_json, account_create, default_headers, generate_string
from app.tests.schemas.schema_account import schema_account_create, schema_account_create_password_length, \
    schema_account_create_username_length, schema_account_create_email_length, schema_account_create_email_invalid, \
    schema_account_create_firstname_length, schema_account_create_lastname_length, schema_account_create_date_invalid, \
    schema_account_create_tos
from app.tests.schemas.schema_system import schema_db_clear, system_running


class SdkTestCase(unittest.TestCase):

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
        print("Testing - test_system_running")
        response = self.app.get('/system/status/')
        unittest.TestCase.assertEqual(self, response.status_code, 200)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, system_running))

    ##########
    ##########
    def test_clear_db_positive(self):
        """
        Test database clearing
        :return:
        """
        print("Testing - test_clear_db_positive")
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
        print("Testing - test_account_create_password_too_long")
        account_json, username, password = account_create(password_length=21)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_password_length))

    def test_account_create_password_too_short(self):
        """
        Test Account creation. Password too short
        :return:
        """
        print("Testing - test_account_create_password_too_short")
        account_json, username, password = account_create(password_length=3)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
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
        print("Testing - test_account_create_username_too_long")
        account_json, username, password = account_create(username_length=256)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_username_length))

    def test_account_create_username_too_short(self):
        """
        Test Account creation. Username too short
        :return:
        """
        print("Testing - test_account_create_username_too_short")
        account_json, username, password = account_create(username_length=2)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
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
        print("Testing - test_account_create_email_too_long")
        account_json, username, password = account_create(email_length=256)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_email_length))

    def test_account_create_email_invalid(self):
        """
        Test Account creation. Email invalid
        :return:
        """
        print("Testing - test_account_create_email_invalid")
        account_json, username, password = account_create(invalid_email=True)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
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
        print("Testing - test_account_create_firstname_too_long")
        account_json, username, password = account_create(firstname_length=256)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_firstname_length))

    def test_account_create_firstname_too_short(self):
        """
        Test Account creation. First name too short
        :return:
        """
        print("Testing - test_account_create_firstname_too_short")
        account_json, username, password = account_create(firstname_length=2)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
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
        print("Testing - test_account_create_lastname_too_long")
        account_json, username, password = account_create(lastname_length=256)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_account_create_lastname_length))

    def test_account_create_lastname_too_short(self):
        """
        Test Account creation. Last name too short
        :return:
        """
        print("Testing - test_account_create_lastname_too_short")
        account_json, username, password = account_create(lastname_length=2)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
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
        print("Testing - test_account_create_date_invalid")
        account_json, username, password = account_create(invalid_date=True)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
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
        print("Testing - test_account_create_tos")
        account_json, username, password = account_create(accept_terms=False)
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
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
        print("Testing - test_account_create_positive")
        account_json, account_username, account_password = account_create()
        response = self.app.post('/api/accounts/', data=account_json, headers=default_headers)
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
        print("Testing - test_account_authenticate")
        account_username, account_password = self.test_account_create_positive()
        print("Using username: " + account_username)
        print("Using password: " + account_password)

        request_headers = default_headers
        request_headers['Authorization'] = 'Basic ' + b64encode("{0}:{1}".format(account_username, account_password))
        print (repr(request_headers))

        response = self.app.get('/api/auth/user/', headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)

if __name__ == '__main__':
    unittest.main()



