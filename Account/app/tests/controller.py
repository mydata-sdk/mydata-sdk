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
import json
from random import choice, randint
from string import lowercase
from time import time
from uuid import uuid4
from jsonschema import validate, ValidationError, SchemaError
from jwcrypto import jwk

default_headers = {'Content-Type': 'application/json', 'Accept-Charset': 'utf-8', 'Accept': 'application/json'}


def print_test_title(test_name=None):
    if test_name is None:
        raise AttributeError("Provide test_name as parameter")
    print("")
    print(test_name)
    print("############")


def get_epoch():
    return int(time())


def get_unique_string():
    return str(uuid4())


def generate_string(n):
    return "".join(choice(lowercase) for i in range(n))


def is_json(json_object=None):
    try:
        json.loads(json_object)
    except Exception as exp:
        raise
    else:
        return True


def validate_json(json_object=None, json_schema=None):
    if json_object is None:
        raise AttributeError("Provide json_object as parameter")
    if json_schema is None:
        raise AttributeError("Provide json_schema as parameter")

    try:
        json_object = json.loads(json_object)
    except Exception as exp:
        raise

    try:
        validate(json_object, json_schema)
    except ValidationError as exp:
        raise
    except SchemaError as exp:
        raise
    except Exception as exp:
        raise
    else:
        return True


def account_create(username=None, password=None, email_length=15, username_length=15, password_length=15, firstname_length=15, lastname_length=15, invalid_email=False, invalid_date=False, invalid_type=False, accept_terms=True):
    """
    Create valid Account
    :return: account, username, password
    """
    if username is None:
        username = generate_string(n=username_length)
    if password is None:
        password = generate_string(n=password_length)
    firstname = generate_string(n=firstname_length)
    lastname = generate_string(n=lastname_length)

    if invalid_email:
        email = generate_string(n=email_length)
    else:
        email = generate_string(n=email_length) + "@examlpe.org"

    if invalid_date:
        # TODO: Case 20160531
        date_of_birth = "20163131"
    else:
        date_of_birth = "2016-05-31"

    if invalid_type:
        resource_type = "Acc"
    else:
        resource_type = "Account"

    if accept_terms:
        accept_tos = True
    else:
        accept_tos = False


    account = {
      "data": {
        "type": resource_type,
        "attributes": {
          "firstName": firstname,
          "lastName": lastname,
          "dateOfBirth": date_of_birth,
          "email": email,
          "username": username,
          "password": password,
          "acceptTermsOfService": accept_tos
        }
      }
    }

    account = json.dumps(account)

    return account, username, password


def generate_sl_init_sink(slr_id=None, misformatted_payload=False):

    if slr_id is None:
        slr_id = get_unique_string()

    code = str(randint(100, 10000))
    pop_key = json.loads(gen_jwk_key(prefix="sink"))

    if misformatted_payload:
        del pop_key['kty']
        del pop_key['x']

    sl_init_payload = {
      "code": code,
      "data": {
        "attributes": {
          "slr_id": slr_id,
          "pop_key": pop_key
        }
      }
    }

    payload = json.dumps(sl_init_payload)

    return payload, code, slr_id, pop_key


def generate_sl_init_source(slr_id=None, misformatted_payload=False):

    if slr_id is None:
        slr_id = get_unique_string()

    code = str(randint(100, 10000))

    sl_init_payload = {
      "code": code,
      "data": {
        "attributes": {
          "slr_id": slr_id
        }
      }
    }

    if misformatted_payload:
        del sl_init_payload['code']

    payload = json.dumps(sl_init_payload)

    return payload, code, slr_id


def generate_sl_payload(slr_id=None, operator_id=None, operator_key=None, service_id=None, surrogate_id=None, misformatted_payload=False):

    if slr_id is None:
        raise AttributeError("Provide operator_id as parameter")
    if operator_id is None:
        raise AttributeError("Provide operator_id as parameter")
    if operator_key is None:
        raise AttributeError("Provide operator_key as parameter")
    if service_id is None:
        raise AttributeError("Provide service_id as parameter")
    if surrogate_id is None:
        raise AttributeError("Provide surrogate_id as parameter")

    if misformatted_payload:
        del operator_key['kty']
        del operator_key['x']

    sl_payload = {
      "code": "string",
      "data": {
        "type": "string",
        "attributes": {
          "version": "1.3",
          "link_id": slr_id,
          "operator_id": operator_id,
          "service_id": service_id,
          "surrogate_id": surrogate_id,
          "operator_key": operator_key,
          "iat": get_epoch()
        }
      }
    }

    payload = json.dumps(sl_payload)

    return payload

#############
#############
# JWS & JWK #
#############
#############


def jwk_object_to_json(jwk_object=None):
    """
    Exports JWK object to JSON presentation

    :param jwk_object:
    :return: JSON presentation of JWK object
    """
    if jwk_object is None:
        raise AttributeError("Provide jwk_object as parameter")

    try:
        jwk_json = jwk_object.export()
    except Exception as exp:
        raise
    else:
        return jwk_json


def gen_key_as_jwk(kid=None):
    """
    Generates JWK (JSON Web Key) object with JWCrypto's jwk module.
    - Module documentation: http://jwcrypto.readthedocs.io/en/stable/jwk.html

    :param kid: Key ID, https://tools.ietf.org/html/rfc7517#section-4.5
    :return: Generated JWK object
    """
    if kid is None:
        raise AttributeError("Provide kid as parameter")
    if not isinstance(kid, str):
        raise TypeError("kid MUST be str")

    gen = {"generate": "EC", "cvr": "P-256", "kid": kid}

    try:
        jwk_key = jwk.JWK(**gen)
        jwk_key_json = jwk_object_to_json(jwk_object=jwk_key)
    except Exception as exp:
        raise
    else:
        return jwk_key_json


def gen_jwk_key(prefix="key"):
    """
    Generate JWK

    :param prefix:
    :return: JWK
    """
    if prefix is None:
        raise AttributeError("Provide prefix as parameter")
    if not isinstance(prefix, str):
        raise TypeError("prefix MUST be str")

    kid = prefix + "-kid-" + str(uuid4())

    try:
        jwk = gen_key_as_jwk(kid=kid)
    except Exception as exp:
        raise
    else:
        return jwk

