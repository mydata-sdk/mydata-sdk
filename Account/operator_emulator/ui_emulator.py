# -*- coding: utf-8 -*-

"""
Minimum viable account - MyData Operator UI Emulator

__author__ = "Jani Yli-Kantola"
__copyright__ = "Digital Health Revolution (c) 2016"
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
__date__ = 12.8.2016
"""
from uuid import uuid4

import requests
import time
from requests.auth import HTTPBasicAuth
import json

request_statuses = []

account_ip = "http://127.0.0.1"
account_port = "8080"
account_host = account_ip+":"+account_port
headers = {'Content-Type': 'application/json'}

account_id = ""
username = "example_username-" + str(uuid4())
password = "example_password"

account_template = {
    "data": {
        "type": "Account",
        "attributes": {
            'firstName': 'ExampleFirstName',
            'lastName': 'ExampleLastName',
            'dateOfBirth': '201-05-14',
            'email': username + '@examlpe.org',
            'username': username,
            'password': password,
            'acceptTermsOfService': 'True'
        }
    }
}





def post(host=None, endpoint=None, headers=None, data=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if endpoint is None:
        raise AttributeError("Provide endpoint as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")
    if data is None:
        raise AttributeError("Provide data as parameter")

    url = host + endpoint
    print("Request")
    print("Endpoint: " + endpoint)
    print("Payload: " + json.dumps(data))

    req = requests.post(url, headers=headers, json=data)
    status_code = str(req.status_code)
    response_data = json.loads(req.text)

    return status_code, response_data


def get(host=None, endpoint=None, headers=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if endpoint is None:
        raise AttributeError("Provide endpoint as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")

    url = host + endpoint
    print("Request")
    print("Endpoint: " + endpoint)

    req = requests.get(url, headers=headers)
    status_code = str(req.status_code)
    response_data = json.loads(req.text)

    return status_code, response_data


######### Actions

# Create Account
print ("------------------------------------")
title = "Create Account"
print(title)
try:
    account = post(host=account_host, endpoint="/api/accounts/", headers=headers, data=account_template)
except Exception as exp:
    print(title + ": " + repr(exp))
else:
    request_statuses.append(title + ": " + account[0])
    account_id = str(account[1]['data'].get("id", "None"))
    print ("Response " + account[0] + ": " + json.dumps(account[1]))
    print ("Account ID: " + account_id)

# Particulars
print ("------------------------------------")
title = "List Particulars"
print(title)
try:
    account = get(host=account_host, endpoint="/api/accounts/" + account_id + "/particulars/", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
else:
    request_statuses.append(title + ": " + account[0])
    particular_id = str(account[1]['data'].get("id", "None"))
    print ("Response " + account[0] + ": " + json.dumps(account[1]))
    print ("particular_id: " + particular_id)

# REPORT
print ("------------------------------------")
print("Request report")
for request in request_statuses:
    print(request)
