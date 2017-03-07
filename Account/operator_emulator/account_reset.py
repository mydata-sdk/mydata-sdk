# -*- coding: utf-8 -*-

"""
Minimum viable account - Account Reset

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


def get(host=None, endpoint=None, headers=None, username=None, password=None):
    if host is None:
        raise AttributeError("Provide host as parameter")
    if endpoint is None:
        raise AttributeError("Provide endpoint as parameter")
    if headers is None:
        raise AttributeError("Provide headers as parameter")

    url = host + endpoint
    print("Endpoint: " + endpoint)
    print("Headers: " + json.dumps(headers))

    if username is not None and password is not None:
        req = requests.get(url, headers=headers, auth=HTTPBasicAuth(username=username, password=password))
    else:
        req = requests.get(url, headers=headers)
    status_code = str(req.status_code)
    print ("Response status: " + str(req.status_code))
    try:
        response_data = json.loads(req.text)
    except Exception as exp:
        print(repr(exp))
        print("req.text: " + repr(req.text))
        response_data = repr(req.text)

    return status_code, response_data


######### Actions

##################################
# Create Account and Authenticate
##################################

#
# Reset
print ("------------------------------------")
title = "Reset"
print(title)
try:
    reset_response = get(host=account_host, endpoint="/system/db/init/salainen", headers=headers)
except Exception as exp:
    print(title + ": " + repr(exp))
    request_response = title + ": " + repr(exp)
    request_statuses.append(request_response)
    raise
else:
    request_response = title + ": " + reset_response[0] + ": " + json.dumps(reset_response[1])
    print('request_response: ' + request_response)
    request_statuses.append(request_response)
    print ("Response: " + request_response)


#################################
# REPORT #
#################################
print ("=====================================")
print("Request report")
for request in request_statuses:
    print(request)

