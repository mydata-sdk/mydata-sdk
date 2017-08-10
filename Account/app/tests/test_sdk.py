# -*- coding: utf-8 -*-

"""
Test Cases for Internal API

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
    generate_sl_init_sink, generate_sl_init_source, gen_jwk_key, generate_sl_payload, \
    generate_sl_store_payload, generate_sls_store_payload, generate_signed_ssr_store_payload, generate_consent_payload, \
    generate_consent_status_payload, generate_consent_status_payload_signed
from app.tests.schemas.schema_account import schema_account_create, schema_account_auth, schema_account_get, schema_account_sdk_info
from app.tests.schemas.schema_authorisation import schema_give_consent, schema_consent_status_change, \
    schema_consent_listing, schema_consent_status_listing, schema_consent_status, schema_consent
from app.tests.schemas.schema_data_connection import schema_authorisation_token_data
from app.tests.schemas.schema_error import schema_request_error_detail_as_str, schema_request_error_detail_as_dict
from app.tests.schemas.schema_service_linking import schema_slr_init, schema_slr_sign, \
    schema_slr_store, schema_slr_listing, schema_slr, schema_slr_status_listing, schema_slr_status, schema_surrogate
from app.tests.schemas.schema_system import schema_db_clear, system_running, schema_sdk_auth, schema_system_status


class SdkTestCase(unittest.TestCase):

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
    def test_system_status(self):
        """
        Test system running
        :return:
        """
        url = '/system/status/'

        response = self.app.get(url)
        unittest.TestCase.assertEqual(self, response.status_code, 200)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_system_status))

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
        response = self.app.get('/system/db/clear/')
        unittest.TestCase.assertEqual(self, response.status_code, 200)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_db_clear))

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

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/auth/sdk/account/" + str(account_id) + "/info/"

        response = self.app.get(url, headers=request_headers)
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

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/sink/"

        payload, code, slr_id, pop_key = generate_sl_init_sink()
        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/sink/"

        payload, code, slr_id, pop_key = generate_sl_init_sink(misformatted_payload=True)

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id_original = self.test_slr_init_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/sink/"
        payload, code, slr_id, pop_key = generate_sl_init_sink(slr_id=slr_id_original)

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/source/"

        payload, code, slr_id = generate_sl_init_source()

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_api_key, account_id = self.test_account_authentication()
        sdk_api_key = self.test_sdk_auth()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/source/"

        payload, code, slr_id = generate_sl_init_source(misformatted_payload=True)

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id_original = self.test_slr_init_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/init/source/"
        payload, code, slr_id = generate_sl_init_source(slr_id=slr_id_original)

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY_PUBLIC,
            service_id=self.SINK_SERVICE_ID,
            surrogate_id=self.SINK_SURROGATE_ID
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_sink()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY_PUBLIC,
            service_id=self.SINK_SERVICE_ID,
            surrogate_id=self.SINK_SURROGATE_ID,
            misformatted_payload=True
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_sink()
        slr_id = "wrong-" + slr_id

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY_PUBLIC,
            service_id=self.SINK_SERVICE_ID,
            surrogate_id=self.SINK_SURROGATE_ID
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_sink()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload, ssr_id = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SINK_SURROGATE_ID,
            service_key=self.SINK_KEY_OBJECT,
            service_kid=self.SINK_KID
        )

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_sink()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload, ssr_id = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SINK_SURROGATE_ID,
            service_key=self.SINK_KEY_OBJECT,
            service_kid=self.SINK_KID,
            misformatted_payload=True
        )

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_sink()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload, ssr_id = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SINK_SURROGATE_ID,
            service_key=self.SINK_KEY_OBJECT,
            service_kid=self.SINK_KID,
            misformatted_signature=True
        )

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY_PUBLIC,
            service_id=self.SOURCE_SERVICE_ID,
            surrogate_id=self.SOURCE_SURROGATE_ID
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY_PUBLIC,
            service_id=self.SOURCE_SERVICE_ID,
            surrogate_id=self.SOURCE_SURROGATE_ID,
            misformatted_payload=True
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id = self.test_slr_init_source()
        slr_id = "wrong-" + slr_id

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/"
        payload = generate_sl_payload(
            slr_id=slr_id,
            operator_id=self.OPERATOR_ID,
            operator_key=self.OPERATOR_KEY_PUBLIC,
            service_id=self.SOURCE_SERVICE_ID,
            surrogate_id=self.SOURCE_SURROGATE_ID
        )

        response = self.app.patch(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_source()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload, ssr_id = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SOURCE_SURROGATE_ID,
            service_key=self.SOURCE_KEY_OBJECT,
            service_kid=self.SOURCE_KID
        )

        response = self.app.post(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 201, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_store))

        return account_id, account_api_key, sdk_api_key, slr_id, ssr_id

    ##########
    ##########
    def test_slr_store_source_malformed(self):
        """
        Test Source SLR storing - Malformed
        :return: account_id, account_api_key, sdk_api_key, slr_id, response.data
        """

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_source()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload, ssr_id = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SOURCE_SURROGATE_ID,
            service_key=self.SOURCE_KEY_OBJECT,
            service_kid=self.SOURCE_KID,
            misformatted_payload=True
        )

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_source()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload, ssr_id = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SOURCE_SURROGATE_ID,
            service_key=self.SOURCE_KEY_OBJECT,
            service_kid=self.SOURCE_KID,
            misformatted_signature=True
        )

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, slr_data = self.test_slr_sign_source()
        slr_data = json.loads(slr_data)

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + slr_id + "/store/"
        payload, ssr_id = generate_sl_store_payload(
            slr_id=slr_id,
            slr_signed=slr_data['data'],
            surrogate_id=self.SINK_SURROGATE_ID,
            service_key=self.SOURCE_KEY_OBJECT,
            service_kid=self.SOURCE_KID
        )

        response = self.app.post(url, data=payload, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_listing))

        # ID verification
        verification_id_array = [slr_id]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr(self):
        """
        Test Fetch SLR
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id = self.test_fetch_slr_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr))

        # ID verification
        verification_id_array = [slr_id]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_wrong_id(self):
        """
        Test Fetch SLR with wrong slr id
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slr_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id_wrong) + "/"

        response = self.app.get(url, headers=request_headers)
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
        
        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status_listing))
        response_data_dict = json.loads(response.data)
        slsr_id = response_data_dict['data'][0]['id']

        # ID verification
        verification_id_array = [ssr_id]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id, slsr_id

    ##########
    ##########
    def test_fetch_slr_status_listing_wrong_id(self):
        """
        Test Fetch SLR status listing with wrong slr_id
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slr_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id_wrong) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_status_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/statuses/" + str(slsr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))

        # ID verification
        verification_id_array = [slsr_id]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id, slsr_id

    ##########
    ##########
    def test_fetch_slr_status_wrong_id(self):
        """
        Test Fetch SLR status by wrong ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_status_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slrs_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/statuses/" + str(slrs_id_wrong) + "/"

        response = self.app.get(url, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_status_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_status))
        response_data_dict = json.loads(response.data)
        slsr_id_from_response = response_data_dict['data']['id']

        # ID verification
        verification_id_array = [slsr_id]
        id_to_verify = str(response_data_dict['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id, slsr_id_from_response

    ##########
    ##########
    def test_fetch_slr_last_status_wrong_id(self):
        """
        Test Fetch SLR last status with wrong slr id
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, slsr_id = self.test_fetch_slr_status_listing()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slr_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(slr_id_wrong) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_listing))

        # ID verification
        verification_id_array = [slr_id]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_with_surrogate_id(self):
        """
        Test Fetch SLR listing for Service with Surrogate ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/?surrogate_id=" + str(self.SOURCE_SURROGATE_ID)

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_listing))

        # ID verification
        verification_id_array = [slr_id]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_with_account_id(self):
        """
        Test Fetch SLR listing for Service with Surrogate ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/?account_id=" + str(account_id)

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_listing))

        # ID verification
        verification_id_array = [slr_id]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_with_account_id_and_surrogate_id(self):
        """
        Test Fetch SLR listing for Service with Surrogate ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/?account_id=" + str(account_id) + "&surrogate_id=" + str(self.SOURCE_SURROGATE_ID)

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr_listing))

        # ID verification
        verification_id_array = [slr_id]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_with_account_id_and_surrogate_id_wrong_surrogate_id(self):
        """
        Test Fetch SLR listing for Service with Surrogate ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/?account_id=" + str(account_id) + "&surrogate_id=" + str(self.SINK_SURROGATE_ID)

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_with_account_id_and_surrogate_id_wrong_account_id(self):
        """
        Test Fetch SLR listing for Service with Surrogate ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/?account_id=" + str(slr_id) + "&surrogate_id=" + str(self.SOURCE_SURROGATE_ID)

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_with_account_id_and_surrogate_id_wrong_account_id_and_surrogate_id(self):
        """
        Test Fetch SLR listing for Service with Surrogate ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/?account_id=" + str(slr_id) + "&surrogate_id=" + str(self.SINK_SURROGATE_ID)

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_with_wrong_surrogate_id(self):
        """
        Test Fetch SLR listing for Service with wrong Surrogate ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/?surrogate_id=" + str(self.SINK_SURROGATE_ID)

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_listing_for_service_wrong_service_id(self):
        """
        Test Fetch SLR listing for Service with wrong ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        service_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/services/" + service_id_wrong + "/servicelinks/"

        response = self.app.get(url, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(slr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_slr))

        # ID verification
        verification_id_array = [slr_id]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_slr_for_service_wrong_service_id(self):
        """
        Test Fetch SLR for Service with wrong Service ID
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        service_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/services/" + service_id_wrong + "/servicelinks/" + str(slr_id) + "/"

        response = self.app.get(url, headers=request_headers)
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

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)
        slr_id_wrong = str(randint(100, 10000))

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(slr_id_wrong) + "/"

        response = self.app.get(url, headers=request_headers)
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

        response = self.app.post(url, data=payload, headers=request_headers)
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

        response = self.app.post(url, data=payload, headers=request_headers)
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

        response = self.app.post(url, data=payload, headers=request_headers)
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

        response = self.app.post(url, data=payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 400, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_dict))

        return account_id, account_api_key, sdk_api_key, slr_id

    ##########
    ##########
    def test_fetch_surrogate_object(self):
        """
        Test Fetch Surrogate object
        :return: account_id, account_api_key, sdk_api_key, slr_id
        """

        account_id, account_api_key, sdk_api_key, slr_id, ssr_id = self.test_slr_store_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/surrogates/" + str(self.SOURCE_SURROGATE_ID) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_surrogate))

        return account_id, account_api_key, sdk_api_key, slr_id

    #################################################################################
    #                                                                               #
    # Complete flow testing with Service Linking, Authorisation and Data Connection #
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
        account_api_key, account_id = self.test_account_authentication()

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
        source_slr_store_payload, ssr_id = generate_sl_store_payload(
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
        sink_slr_store_payload, ssr_id = generate_sl_store_payload(
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
    def test_for_account_give_consent(self):
        """
        Give Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        # Give Consent
        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

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

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_give_consent_multiple(self):
        """
        Give Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        # Give Consent
        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

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

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_give_consent_malformed(self):
        """
        Give Consent - With incorrect payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

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
                misformatted_payload=True
        )

        give_consent_response = self.app.post(give_consent_url, data=give_consent_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, give_consent_response.status_code, 400, msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, validate_json(give_consent_response.data, schema_request_error_detail_as_dict))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_give_consent_wrong_source_surrogate_id(self):
        """
        Give Consent - With incorrect payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        give_consent_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + source_slr_id + "/" + sink_slr_id + "/consents/"
        give_consent_payload, source_cr_id, source_csr_id, sink_cr_id, sink_csr_id = generate_consent_payload(
                source_surrogate_id="wrong-id",
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
        unittest.TestCase.assertEqual(self, give_consent_response.status_code, 400, msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, validate_json(give_consent_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_give_consent_unknown_sink_surrogate_id(self):
        """
        Give Consent - With incorrect payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        give_consent_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + source_slr_id + "/" + sink_slr_id + "/consents/"
        give_consent_payload, source_cr_id, source_csr_id, sink_cr_id, sink_csr_id = generate_consent_payload(
                source_surrogate_id=self.SOURCE_SURROGATE_ID,
                source_slr_id=source_slr_id,
                operator_id=self.OPERATOR_ID,
                source_subject_id=self.SOURCE_SERVICE_ID,
                sink_pop_key=self.SINK_KEY_PUBLIC,
                operator_pub_key=self.OPERATOR_KEY_PUBLIC,
                sink_surrogate_id="unknown",
                sink_slr_id=sink_slr_id,
                sink_subject_id=self.SINK_SERVICE_ID,
                misformatted_payload=False
        )

        give_consent_response = self.app.post(give_consent_url, data=give_consent_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, give_consent_response.status_code, 400, msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, validate_json(give_consent_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_give_consent_unknown_source_slr_id(self):
        """
        Give Consent - With incorrect payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        give_consent_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + source_slr_id + "/" + sink_slr_id + "/consents/"
        give_consent_payload, source_cr_id, source_csr_id, sink_cr_id, sink_csr_id = generate_consent_payload(
                source_surrogate_id=self.SOURCE_SURROGATE_ID,
                #source_slr_id=source_slr_id,
                source_slr_id="unknown",
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
        unittest.TestCase.assertEqual(self, give_consent_response.status_code, 400, msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, validate_json(give_consent_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_give_consent_wrong_sink_slr_id(self):
        """
        Give Consent - With incorrect payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        give_consent_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + source_slr_id + "/" + sink_slr_id + "/consents/"
        give_consent_payload, source_cr_id, source_csr_id, sink_cr_id, sink_csr_id = generate_consent_payload(
                source_surrogate_id=self.SOURCE_SURROGATE_ID,
                source_slr_id=source_slr_id,
                operator_id=self.OPERATOR_ID,
                source_subject_id=self.SOURCE_SERVICE_ID,
                sink_pop_key=self.SINK_KEY_PUBLIC,
                operator_pub_key=self.OPERATOR_KEY_PUBLIC,
                sink_surrogate_id=self.SINK_SURROGATE_ID,
                sink_slr_id="wrong_id",
                sink_subject_id=self.SINK_SERVICE_ID,
                misformatted_payload=False
        )

        give_consent_response = self.app.post(give_consent_url, data=give_consent_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, give_consent_response.status_code, 400, msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, validate_json(give_consent_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_give_consent_wrong_source_cr_id_pair(self):
        """
        Give Consent - With incorrect payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

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
                misformatted_payload=False,
                source_cr_id_fault=True,
                sink_cr_id_fault=False
        )

        give_consent_response = self.app.post(give_consent_url, data=give_consent_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, give_consent_response.status_code, 400, msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, validate_json(give_consent_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_give_consent_wrong_sink_cr_id_pair(self):
        """
        Give Consent - With incorrect payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

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
                misformatted_payload=False,
                source_cr_id_fault=False,
                sink_cr_id_fault=True
        )

        give_consent_response = self.app.post(give_consent_url, data=give_consent_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, give_consent_response.status_code, 400, msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, validate_json(give_consent_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

        ##########
        ##########
    def test_for_account_give_consent_surrogate_id_mismatch_source(self):
        """
        Give Consent - With incorrect payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        give_consent_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(
            account_id) + "/servicelinks/" + source_slr_id + "/" + sink_slr_id + "/consents/"
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
            misformatted_payload=False,
            source_cr_id_fault=False,
            sink_cr_id_fault=False,
            source_surrogate_id_fault=True,
            sink_surrogate_id_fault=False
        )

        give_consent_response = self.app.post(give_consent_url, data=give_consent_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, give_consent_response.status_code, 400, msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self,validate_json(give_consent_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

        ##########
        ##########
    def test_for_account_give_consent_surrogate_id_mismatch_sink(self):
        """
        Give Consent - With incorrect payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id = self.test_for_account_link_services()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        give_consent_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(
            account_id) + "/servicelinks/" + source_slr_id + "/" + sink_slr_id + "/consents/"
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
            misformatted_payload=False,
            source_cr_id_fault=False,
            sink_cr_id_fault=False,
            source_surrogate_id_fault=False,
            sink_surrogate_id_fault=True
        )

        give_consent_response = self.app.post(give_consent_url, data=give_consent_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, give_consent_response.status_code, 400, msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=give_consent_response.data), msg=give_consent_response.data)
        unittest.TestCase.assertTrue(self,validate_json(give_consent_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_change_consent_status_source(self):
        """
        Change Consent Status - Source Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_give_consent()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

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

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_change_consent_status_sink(self):
        """
        Change Consent Status - Sink Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id, sink_csr_id_new
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

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

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id, sink_csr_id_new

    ##########
    ##########
    def test_for_account_change_consent_status_incorrect_cr_id(self):
        """
        Change Consent Status - Faulty payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_give_consent()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        # Change Consent Status of Source Service
        consent_status_change_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + source_cr_id + "/statuses/"
        consent_status_change_payload, source_csr_id_new = generate_consent_status_payload(
            surrogate_id=self.SOURCE_SURROGATE_ID,
            cr_id=source_cr_id,
            consent_status="Paused",
            prev_record_id=source_csr_id,
            misformatted_payload=False,
            cr_id_fault=True
        )

        consent_status_change_response = self.app.post(consent_status_change_url, data=consent_status_change_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 400, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_change_consent_status_incorrect_payload(self):
        """
        Change Consent Status - Faulty payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_give_consent()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        # Change Consent Status of Source Service
        consent_status_change_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + source_cr_id + "/statuses/"
        consent_status_change_payload, source_csr_id_new = generate_consent_status_payload(
            surrogate_id=self.SOURCE_SURROGATE_ID,
            cr_id=source_cr_id,
            consent_status="Paused",
            prev_record_id=source_csr_id,
            misformatted_payload=True,
            cr_id_fault=False
        )

        consent_status_change_response = self.app.post(consent_status_change_url, data=consent_status_change_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 400, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_request_error_detail_as_dict))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_change_consent_status_unknown_consent(self):
        """
        Change Consent Status - Faulty payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_give_consent()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        source_cr_id = "unknown-" + source_cr_id

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
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 400, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_change_consent_status_signed_source(self):
        """
        Change Consent Status by Operator - Source Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_give_consent()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        # Change Consent Status of Source Service
        consent_status_change_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + source_cr_id + "/statuses/signed/"
        consent_status_change_payload, source_csr_id_new = generate_consent_status_payload_signed(
            surrogate_id=self.SOURCE_SURROGATE_ID,
            cr_id=source_cr_id,
            consent_status="Paused",
            prev_record_id=source_csr_id,
            misformatted_payload=False,
            cr_id_fault=False,
            operator_kid=self.OPERATOR_KID,
            operator_key=self.OPERATOR_KEY_OBJECT
        )

        consent_status_change_response = self.app.post(consent_status_change_url, data=consent_status_change_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 201, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_consent_status_change))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_change_consent_status_signed_sink(self):
        """
        Change Consent Status by Operator - Sink Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id, sink_csr_id_new
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_signed_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        # Change Consent Status of Source Service
        consent_status_change_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + sink_cr_id + "/statuses/signed/"
        consent_status_change_payload, sink_csr_id_new = generate_consent_status_payload_signed(
            surrogate_id=self.SINK_SURROGATE_ID,
            cr_id=sink_cr_id,
            consent_status="Paused",
            prev_record_id=sink_csr_id,
            misformatted_payload=False,
            cr_id_fault=False,
            operator_kid=self.OPERATOR_KID,
            operator_key=self.OPERATOR_KEY_OBJECT
        )

        consent_status_change_response = self.app.post(consent_status_change_url, data=consent_status_change_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 201, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_consent_status_change))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id, sink_csr_id_new

    ##########
    ##########
    def test_for_account_change_consent_status_signed_incorrect_payload(self):
        """
        Change Consent Status by Operator - Faulty payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_give_consent()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        # Change Consent Status of Source Service
        consent_status_change_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + source_cr_id + "/statuses/signed/"
        consent_status_change_payload, source_csr_id_new = generate_consent_status_payload_signed(
            surrogate_id=self.SOURCE_SURROGATE_ID,
            cr_id=source_cr_id,
            consent_status="Paused",
            prev_record_id=source_csr_id,
            misformatted_payload=True,
            cr_id_fault=False,
            operator_kid=self.OPERATOR_KID,
            operator_key=self.OPERATOR_KEY_OBJECT
        )

        consent_status_change_response = self.app.post(consent_status_change_url, data=consent_status_change_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 400, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_request_error_detail_as_dict))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_change_consent_status_signed_incorrect_cr_id(self):
        """
        Change Consent Status by Operator - Faulty payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_give_consent()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        # Change Consent Status of Source Service
        consent_status_change_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + source_cr_id + "/statuses/signed/"
        consent_status_change_payload, source_csr_id_new = generate_consent_status_payload_signed(
            surrogate_id=self.SOURCE_SURROGATE_ID,
            cr_id=source_cr_id,
            consent_status="Paused",
            prev_record_id=source_csr_id,
            misformatted_payload=False,
            cr_id_fault=True,
            operator_kid=self.OPERATOR_KID,
            operator_key=self.OPERATOR_KEY_OBJECT
        )

        consent_status_change_response = self.app.post(consent_status_change_url, data=consent_status_change_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 400, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_change_consent_status_signed_unknown_cr_id(self):
        """
        Change Consent Status by Operator - Faulty payload
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_give_consent()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        source_cr_id = "unknown-" + source_cr_id

        # Change Consent Status of Source Service
        consent_status_change_url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + source_cr_id + "/statuses/signed/"
        consent_status_change_payload, source_csr_id_new = generate_consent_status_payload_signed(
            surrogate_id=self.SOURCE_SURROGATE_ID,
            cr_id=source_cr_id,
            consent_status="Paused",
            prev_record_id=source_csr_id,
            misformatted_payload=False,
            cr_id_fault=False,
            operator_kid=self.OPERATOR_KID,
            operator_key=self.OPERATOR_KEY_OBJECT
        )

        consent_status_change_response = self.app.post(consent_status_change_url, data=consent_status_change_payload, headers=request_headers)
        unittest.TestCase.assertEqual(self, consent_status_change_response.status_code, 400, msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=consent_status_change_response.data), msg=consent_status_change_response.data)
        unittest.TestCase.assertTrue(self, validate_json(consent_status_change_response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consents_by_link(self):
        """
        Test Consents
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = source_cr_id_array
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id

    ##########
    ##########
    def test_for_account_fetch_consents_by_link_with_consent_pairs(self):
        """
        Test Consents
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/?get_consent_pair=True"
        count *= 2

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = source_cr_id_array + sink_cr_id_array
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consents_by_link_wrong_slr_id(self):
        """
        Test Consents - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/consents/?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consents_by_link_with_consent_pairs_wrong_slr_id(self):
        """
        Test Consents - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/consents/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consents_by_link_wrong_account_id(self):
        """
        Test Consents - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(sink_slr_id) + "/servicelinks/" + str(source_slr_id) + "/consents/?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id

    ##########
    ##########
    def test_for_account_fetch_consent_by_link(self):
        """
        Test Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "?get_consent_pair=False"
        count = 1

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = [source_cr_id_array[0]]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consent_by_link_with_consent_pair(self):
        """
        Test Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "?get_consent_pair=True"
        count = 2

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = [source_cr_id_array[0], sink_cr_id_array[0]]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consent_by_link_wrong_slr_id(self):
        """
        Test Consents - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/consents/" + str(source_cr_id_array[0]) + "/?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consent_by_link_with_consent_pairs_wrong_slr_id(self):
        """
        Test Consents - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/consents/" + str(source_cr_id_array[0]) + "/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consent_by_link_wrong_account_id(self):
        """
        Test Consent - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(sink_slr_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "/?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_last_consent_by_link(self):
        """
        Test Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/last/?get_consent_pair=False"
        count = 1

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = [source_cr_id_array[-1]]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_last_consent_by_link_with_consent_pair(self):
        """
        Test Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/last/?get_consent_pair=True"
        count = 2

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = [source_cr_id_array[-1], sink_cr_id_array[-1]]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_last_consent_by_link_wrong_slr_id(self):
        """
        Test Consents - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/consents/last/?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_last_consent_by_link_with_consent_pairs_wrong_slr_id(self):
        """
        Test Consents - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_ssr_id) + "/consents/last/?get_consent_pair=True"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_last_consent_by_link_wrong_account_id(self):
        """
        Test Consent - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(sink_slr_id) + "/servicelinks/" + str(source_slr_id) + "/consents/last/?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consents(self):
        """
        Test Consents
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/"
        count *= 2

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = source_cr_id_array + sink_cr_id_array
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consents_wrong_account_id(self):
        """
        Test Consents - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(sink_slr_id) + "/consents/?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id

    ##########
    ##########
    def test_for_account_fetch_consent_by_account(self):
        """
        Test Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(source_cr_id_array[0]) + "/?get_consent_pair=False"
        count = 1

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = [source_cr_id_array[0]]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consent_by_account_with_consent_pair(self):
        """
        Test Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(source_cr_id_array[0]) + "?get_consent_pair=True"
        count = 2

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = [source_cr_id_array[0], sink_cr_id_array[0]]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consent_by_account_with_wrong_consent_id(self):
        """
        Test Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(sink_slr_id) + "?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consent_by_account_with_wrong_account_id(self):
        """
        Test Consent
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(source_slr_id) + "/consents/" + str(source_cr_id_array[0]) + "?get_consent_pair=False"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_for_account_fetch_consent_statuses_by_account_and_consent(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(source_cr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status_listing))

        # ID verification
        verification_id_array = [source_csr_id, source_csr_id_new]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_statuses_by_account_and_consent_with_status_filter(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(source_cr_id) + "/statuses/?status_id=" + str(source_csr_id)
        count = 1

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status_listing))
        unittest.TestCase.assertEqual(self, len(json.loads(response.data)['data']), count, msg="Response array is containing {} objects instead of {} expexted objects".format(len(json.loads(response.data)['data']), count))

        # ID verification
        verification_id_array = [source_csr_id_new]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_statuses_by_account_and_consent_with_wrong_consent_id(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(sink_slr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_statuses_by_account_and_consent_with_status_filter_faulty(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(source_cr_id) + "/statuses/?status_id=faulty_id"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_status_by_account_and_consent(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(source_cr_id) + "/statuses/" + str(source_csr_id) +"/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status))

        # ID verification
        verification_id_array = [source_csr_id]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_status_by_account_and_consent_wrong_consent_status_id(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(source_cr_id) + "/statuses/" + str(sink_csr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_statuses_by_account_and_link_and_consent(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status_listing))

        # ID verification
        verification_id_array = [source_csr_id, source_csr_id_new]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_statuses_by_account_and_link_and_consent_wrong_link_id(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(sink_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_statuses_by_account_and_link_and_consent_wrong_consent_id(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(sink_cr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_status_by_account_and_link_and_consent(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/" + str(source_csr_id_new) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status))

        # ID verification
        verification_id_array = [source_csr_id_new]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_status_by_account_and_link_and_consent_wrong_link_id(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(sink_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/" + str(source_csr_id_new) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_status_by_account_and_link_and_consent_wrong_consent_id(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(sink_cr_id) + "/statuses/" + str(source_csr_id_new) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_status_by_account_and_link_and_consent_wrong_status_id(self):
        """
        Test Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/" + str(sink_csr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_last_status_by_account_and_consent(self):
        """
        Test Last Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(source_cr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status))

        # ID verification
        verification_id_array = [source_csr_id_new]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_last_status_by_account_and_consent_with_wrong_consent_id(self):
        """
        Test Last Consent Status - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/consents/" + str(source_ssr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_last_status_by_account_and_consent_with_wrong_account_id(self):
        """
        Test Last Consent Status - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_last_status_by_account_and_link_and_consent(self):
        """
        Test Last Consent Status
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status))

        # ID verification
        verification_id_array = [source_csr_id_new]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_last_status_by_account_and_link_and_consent_with_wrong_consent_id(self):
        """
        Test Last Consent Status - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(account_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_ssr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_account_fetch_consent_last_status_by_account_and_link_and_consent_with_wrong_account_id(self):
        """
        Test Last Consent Status - Invalid IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-User'] = str(account_api_key)
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/accounts/" + str(source_slr_id) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 403, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##
    # TEST CASES FOR SERVICES
    ##########
    ##########
    def test_for_service_fetch_consents(self):
        """
        Consent listing for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_listing))

        # ID verification
        verification_id_array = [source_cr_id]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consents_wrong_service_id(self):
        """
        Consent listing for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SINK_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consents_wrong_link_id(self):
        """
        Consent listing for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(sink_slr_id) + "/consents/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent(self):
        """
        Consent for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent))

        # ID verification
        verification_id_array = [source_cr_id]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_wrong_service_id(self):
        """
        Consent for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SINK_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_wrong_link_id(self):
        """
        Consent for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(sink_slr_id) + "/consents/" + str(source_cr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_wrong_consent_id(self):
        """
        Consent for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(sink_cr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_statuses(self):
        """
        Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status_listing))

        # ID verification
        verification_id_array = [source_csr_id, source_csr_id_new]
        for record_object in json.loads(response.data)['data']:
            id_to_verify = str(record_object['id'])
            unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_statuses_wrong_service_id(self):
        """
        Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SINK_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_statuses_wrong_link_id(self):
        """
        Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(sink_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_statuses_wrong_consent_id(self):
        """
        Consent Statuses for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(sink_cr_id) + "/statuses/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_status(self):
        """
        Consent Status for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/" + str(source_csr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status))

        # ID verification
        verification_id_array = [source_csr_id]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_status_wrong_service_id(self):
        """
        Consent Status for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SINK_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/" + str(source_csr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_status_wrong_link_id(self):
        """
        Consent Status for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(sink_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/" + str(source_csr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_status_wrong_consent_id(self):
        """
        Consent Status for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(sink_cr_id) + "/statuses/" + str(source_csr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_consent_status_wrong_consent_status_id(self):
        """
        Consent Status for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/" + str(sink_csr_id) + "/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_last_consent_status(self):
        """
        Last Consent Status for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_consent_status))

        # ID verification
        verification_id_array = [source_csr_id_new]
        id_to_verify = str(json.loads(response.data)['data']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_last_consent_status_wrong_service_id(self):
        """
        Last Consent Status for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SINK_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_last_consent_status_wrong_link_id(self):
        """
        Last Consent Status for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(sink_slr_id) + "/consents/" + str(source_cr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_for_service_fetch_last_consent_status_wrong_consent_id(self):
        """
        Last Consent Status for Service
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id = self.test_for_account_change_consent_status_source()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/services/" + str(self.SOURCE_SERVICE_ID) + "/servicelinks/" + str(source_slr_id) + "/consents/" + str(sink_cr_id) + "/statuses/last/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, source_cr_id, source_csr_id, source_csr_id_new, sink_slr_id, sink_ssr_id, sink_cr_id, sink_csr_id

    ##########
    ##########
    def test_authorisation_token_data(self):
        """
        Authorisation token data
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/consents/" + str(sink_cr_id_array[0]) + "/authorisationtoken/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 200, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_authorisation_token_data))

        # ID verification

        ## Source's Consent Record
        verification_id_array = [source_cr_id_array[0]]
        id_to_verify = str(json.loads(response.data)['data']['consent_record']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="Source's Consent Record ID {} not one of {}".format(id_to_verify, verification_id_array))

        ## Sink's Service Link Record
        verification_id_array = [sink_slr_id]
        id_to_verify = str(json.loads(response.data)['data']['service_link_record']['id'])
        unittest.TestCase.assertIn(self, id_to_verify, verification_id_array, msg="Sink's Service Link Record ID {} not one of {}".format(id_to_verify, verification_id_array))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

    ##########
    ##########
    def test_authorisation_token_data_wrong_consent_id(self):
        """
        Authorisation token data - Faulty IDs
        :return: account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count
        """

        account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count = self.test_for_account_give_consent_multiple()

        request_headers = default_headers
        request_headers['Api-Key-Sdk'] = str(sdk_api_key)

        url = self.API_PREFIX_INTERNAL + "/consents/" + str(source_cr_id_array[0]) + "/authorisationtoken/"

        response = self.app.get(url, headers=request_headers)
        unittest.TestCase.assertEqual(self, response.status_code, 404, msg=response.data)
        unittest.TestCase.assertTrue(self, is_json(json_object=response.data), msg=response.data)
        unittest.TestCase.assertTrue(self, validate_json(response.data, schema_request_error_detail_as_str))

        return account_id, account_api_key, sdk_api_key, source_slr_id, source_ssr_id, sink_slr_id, sink_ssr_id, source_cr_id_array, source_csr_id_array, sink_cr_id_array, sink_csr_id_array, count

if __name__ == '__main__':
    unittest.main()
