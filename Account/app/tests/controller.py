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
from random import choice
from string import lowercase
from uuid import uuid4
from jsonschema import validate, ValidationError, SchemaError

default_headers = {'Content-Type': 'application/json', 'Accept-Charset': 'utf-8', 'Accept': 'application/json'}


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


def account_create(email_length=15, username_length=15, password_length=15, firstname_length=15, lastname_length=15, invalid_email=False, invalid_date=False, invalid_type=False, accept_terms=True):
    """
    Create valid Account
    :return: account, username, password
    """
    username = generate_string(n=username_length)
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
