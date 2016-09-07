# -*- coding: utf-8 -*-
import json
import argparse
from requests import get, post

# TODO: Maybe these should be given as parameters
Service_ID_A = 10
Service_ID_B = 100


# TODO: Add printing. Now user doesn't know if initialization happened and did it succeed or not.
# Sends JSON-payloads to Account that create three new accounts.
# Needed in order to start_ui_flow() -function to work.
def initialize(operator_url):
    print("Initializing....")
    post(operator_url + '/api/accounts/',
         json={"firstName": "Erkki", "lastName": "Esimerkki", "dateOfBirth": "31-05-2016",
               "email": "erkki.esimerkki@examlpe.org", "username": "testUffser", "password": "Hello",
               "acceptTermsOfService": "True"})
    post(operator_url + '/api/accounts/',
         json={"firstName": "Iso", "lastName": "Pasi", "dateOfBirth": "31-05-2016", "email": "iso.pasi@examlpe.org",
               "username": "pasi", "password": "0nk0va", "acceptTermsOfService": "True"})
    post(operator_url + '/api/accounts/', json={"firstName": "Dude", "lastName": "Dudeson", "dateOfBirth": "31-05-2016",
                                                "email": "dude.dudeson@examlpe.org", "username": "mydata",
                                                "password": "Hello", "acceptTermsOfService": "True"})
    return


# TODO: Refactor and return something.
# First creates two Service Links by making a GET-request to Operator backend.
# Then gives a Consent for these Services by sending a Consent form as JSON-payload to Operator backend.
# Should print "201 Created" if the flow was excuted succesfully.
def start_ui_flow(operator_url):
    slr_flow1 = get(operator_url + "api/1.2/slr/account/2/service/1")
    print(slr_flow1.url, slr_flow1.reason, slr_flow1.status_code, slr_flow1.text)
    slr_flow2 = get(operator_url + "api/1.2/slr/account/2/service/2")
    print(slr_flow2.url, slr_flow2.reason, slr_flow2.status_code, slr_flow2.text)

    # This format needs to be specified, even if done with url params instead.
    ids = {"sink": Service_ID_B, "source": Service_ID_A}

    req = get(operator_url + "api/1.2/cr/consent_form/account/2?sink={}&source={}".format(Service_ID_B, Service_ID_A))

    print(req.url, req.reason, req.status_code, req.text)
    js = json.loads(req.text)

    req = post(operator_url + "api/1.2/cr/consent_form/account/2", json=js)

    print(req.url, req.reason, req.status_code, "\n", json.dumps(json.loads(req.text), indent=2))

    return


if __name__ == '__main__':

    # Parse command line arguments
    parser = argparse.ArgumentParser()

    # TODO: Use boolean value instead of int.
    help_string_initialize = \
        "Should database be initialized. Set to non-zero to initialize. Note that this is required if system has been started for the first time. Defaults to False. e.g '--initialize True'."
    parser.add_argument("--initialize",
                        help=help_string_initialize,
                        type=str,
                        default=None,
                        required=False)

    help_string_operator_url = \
        "URL to Operator backend. Defaults to 'http://localhost:5000/'."
    parser.add_argument("--operator_url",
                        help=help_string_operator_url,
                        type=str,
                        default="http://localhost:5000/",
                        required=False)

    args = parser.parse_args()

    if args.initialize is not None:
        initialize(args.operator_url)

    start_ui_flow(args.operator_url)
