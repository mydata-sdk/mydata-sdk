# -*- coding: utf-8 -*-
import json
import argparse
from requests import get, post
from uuid import uuid4
# TODO: Maybe these should be given as parameters
Service_ID_Source   = "582b7df00cf2727145535753"  # MyLocation
Service_ID_Sink     = "582b7df00cf2727145535754"  # PHR


# TODO: Add more printing. Now user barely knows if initialization happened and did it succeed or not.
# Sends JSON-payloads to Account that create three new accounts.
# Needed in order to start_ui_flow() -function to work.
def initialize(operator_url):
    username = "example_username-" + str(uuid4())
    password = "example_password"

    print ("\n##### CREATE USER ACCOUNTS #####")
    print("NOTE: Throws an error if run for second time as you cannot "
          "create more accounts with same unique usernames. "
          "(Will be fixed in later releases.)\n\n"
         )
    user_data = {"data": {
        "type": "Account",
        "attributes": {
            'firstName': 'ExampleFirstName',
            'lastName': 'ExampleLastName',
            'dateOfBirth': '2010-05-14',
            'email': username + '@examlpe.org',
            'username': username,
            'password': password,
            'acceptTermsOfService': 'True'
        }
    }
}
    resp = post(operator_url + 'api/accounts/',
                json=user_data)
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))

    user_data["data"]["attributes"]["firstName"] = "Iso"
    user_data["data"]["attributes"]["lastName"] = "Pasi"
    user_data["data"]["attributes"]["email"] = "iso.pasi@example.org"
    user_data["data"]["attributes"]["username"] = "pasi"
    user_data["data"]["attributes"]["password"] = "0nk0va"
    resp = post(operator_url + 'api/accounts/',
                json=user_data)
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))

    user_data["data"]["attributes"]["firstName"] = "Dude"
    user_data["data"]["attributes"]["lastName"] = "Dudeson"
    user_data["data"]["attributes"]["email"] = "dude.dudeson@example.org"
    user_data["data"]["attributes"]["username"] = "mydata"
    user_data["data"]["attributes"]["password"] = "Hello"
    resp = post(operator_url + 'api/accounts/',
                json=user_data)
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))
    # post(operator_url + 'api/accounts/',
    #      json={"firstName": "Iso", "lastName": "Pasi", "dateOfBirth": "31-05-2016", "email": "iso.pasi@examlpe.org",
    #            "username": "pasi", "password": "0nk0va", "acceptTermsOfService": "True"})
    # post(operator_url + 'api/accounts/', json={"firstName": "Dude", "lastName": "Dudeson", "dateOfBirth": "31-05-2016",
    #                                            "email": "dude.dudeson@examlpe.org", "username": "mydata",
    #                                            "password": "Hello", "acceptTermsOfService": "True"})
    return


# TODO: Refactor and return something.
# First creates two Service Links by making a GET-request to Operator backend.
# Then gives a Consent for these Services by sending a Consent form as JSON-payload to Operator backend.
# Should print "201 Created" if the flow was excuted succesfully.
def start_ui_flow(operator_url):
    print("\n##### MAKE TWO SERVICE LINKS #####")
    slr_flow1 = get(operator_url + "api/1.2/slr/account/2/service/"+Service_ID_Sink)
    if not slr_flow1.ok:
        print("Creation of first SLR failed with status ({}) reason ({}) and the following content:\n{}".format(
            slr_flow1.status_code,
            slr_flow1.reason,
            json.dumps(json.loads(slr_flow1.content), indent=2)
        ))
        raise Exception("SLR flow failed.")
    print(slr_flow1.url, slr_flow1.reason, slr_flow1.status_code, slr_flow1.text)
    slr_flow2 = get(operator_url + "api/1.2/slr/account/2/service/"+Service_ID_Source)
    if not slr_flow2.ok:
        print("Creation of second SLR failed with status ({}) reason ({}) and the following content:\n{}".format(
            slr_flow2.status_code,
            slr_flow2.reason,
            json.dumps(json.loads(slr_flow2.content), indent=2)
        ))
        raise Exception("SLR flow failed.")
    print(slr_flow2.url, slr_flow2.reason, slr_flow2.status_code, slr_flow2.text)

    # This format needs to be specified, even if done with url params instead.
    ids = {"sink": Service_ID_Sink, "source": Service_ID_Source}

    print("\n##### GIVE CONSENT #####")
    req = get(operator_url + "api/1.2/cr/consent_form/account/2?sink={}&source={}".format(Service_ID_Sink, Service_ID_Source))
    if not req.ok:
        print("Fetching consent form consent failed with status ({}) reason ({}) and the following content:\n{}".format(
            req.status_code,
            req.reason,
            json.dumps(json.loads(req.content), indent=2)
        ))
        raise Exception("Consent flow failed.")


    print(req.url, req.reason, req.status_code, req.text)
    js = json.loads(req.text)
    req = post(operator_url + "api/1.2/cr/consent_form/account/2", json=js)
    if not req.ok:
        print("Granting consent failed with status ({}) reason ({}) and the following content:\n{}".format(
            req.status_code,
            req.reason,
            json.dumps(json.loads(req.content), indent=2)
        ))
        raise Exception("Consent flow failed.")

    print(req.url, req.reason, req.status_code)
    print("\n")
    print(json.dumps(json.loads(req.text), indent=2))

    print("\n\n")
    return


if __name__ == '__main__':

    # Parse command line arguments
    parser = argparse.ArgumentParser()

    # TODO: Use boolean value instead of int.
    help_string_account_url = \
        "URL to Account. Defaults to 'http://localhost:8080'. \
        NOTE: Throws an error if run for second time as you cannot\
        create more accounts with same unique usernames.\
        (Will be fixed in later releases.)"
    parser.add_argument("--account_url",
                        help=help_string_account_url,
                        type=str,
                        default="http://localhost:8080/",
                        required=False)

    help_string_operator_url = \
        "URL to Operator backend. Defaults to 'http://localhost:5000/'."
    parser.add_argument("--operator_url",
                        help=help_string_operator_url,
                        type=str,
                        default="http://localhost:5000/",
                        required=False)

    args = parser.parse_args()

    initialize(args.account_url)

    start_ui_flow(args.operator_url)
