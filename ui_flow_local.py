# -*- coding: utf-8 -*-

import json
import argparse, time
from requests import get, post, delete
from uuid import uuid4
from base64 import urlsafe_b64decode as decode
from base64 import urlsafe_b64encode as encode

# TODO: Maybe these should be given as parameters
#Service_ID_Source   = "57f3a57b0cf2fcf22eea33a2"  # MyLocation
#Service_ID_Sink     = "57f3a57b0cf2fcf22eea33a3"  # PHR
#Service_ID_Source   = "582b7df00cf2727145535753"  # MyLocation
#Service_ID_Sink     = "582b7df00cf2727145535754"  # PHR
Service_ID_Source   = "582f2bf50cf2f4663ec4f01f"  # MyLocation
Service_ID_Sink     = "582f2bf50cf2f4663ec4f020"  # PHR

# TODO: Add more printing. Now user barely knows if initialization happened and did it succeed or not.
# Sends JSON-payloads to Account that create three new accounts.
# Needed in order to start_ui_flow() -function to work.
def initialize(account_url):

    def get_api_key(account_url=account_url, account=("pasi", "0nk0va"), endpoint="external/auth/user/"):
        print("\nFetching Account Key for account '{}'".format(account[0]))
        api_json = get(account_url+endpoint, auth=account).text
        print("Received following key:\n {}".format(api_json))
        return api_json

    username = "example_username-" + str(uuid4())
    password = "example_password"
    create_endpoint = "external/accounts/"

    print ("\n##### CREATE USER ACCOUNTS #####")
    print("NOTE: Throws an error if run for second time as you cannot "
          "create more accounts with same unique usernames. "
          "(Will be fixed in later releases.)\n\n"
         )
    user_data = {"data": {
        "type": "Account",
        "attributes": {
            'firstname': 'ExampleFirstName',
            'lastname': 'ExampleLastName',
            'dateOfBirth': '2010-05-14',
            'email': username + '@examlpe.org',
            'username': username,
            'password': password,
            'acceptTermsOfService': True
            }
          }
        }
    resp = post(account_url + create_endpoint,
                json=user_data)
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))

    user_data["data"]["attributes"]["firstname"] = "Iso"
    user_data["data"]["attributes"]["lastname"] = "Pasi"
    user_data["data"]["attributes"]["email"] = "iso.pasi@example.org"
    user_data["data"]["attributes"]["username"] = "pasi"
    user_data["data"]["attributes"]["password"] = "0nk0va"
    resp = post(account_url + create_endpoint,
                json=user_data)
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))

    user_data["data"]["attributes"]["firstname"] = "Dude"
    user_data["data"]["attributes"]["lastname"] = "Dudeson"
    user_data["data"]["attributes"]["email"] = "dude.dudeson@example.org"
    user_data["data"]["attributes"]["username"] = "mydata"
    user_data["data"]["attributes"]["password"] = "Hello"
    resp = post(account_url + create_endpoint,
                json=user_data)
    print(resp.status_code, resp.reason, resp.text, resp.url)
    print(json.dumps(json.loads(resp.text), indent=2))
    # post(account_url + 'api/accounts/',
    #      json={"firstName": "Iso", "lastName": "Pasi", "dateOfBirth": "31-05-2016", "email": "iso.pasi@examlpe.org",
    #            "username": "pasi", "password": "0nk0va", "acceptTermsOfService": "True"})
    # post(operator_url + 'api/accounts/', json={"firstName": "Dude", "lastName": "Dudeson", "dateOfBirth": "31-05-2016",
    #                                            "email": "dude.dudeson@examlpe.org", "username": "mydata",
    #                                            "password": "Hello", "acceptTermsOfService": "True"})

    return json.loads(get_api_key())

# TODO: Refactor and return something.
# Creates two Service Links by making a GET-request to Operator backend.
def create_service_link(operator_url, service_id, user_key):
    print("\n##### CREATE A SERVICE LINK #####")
    print("User key is: {}".format(user_key["Api-Key-User"]))
    slr_flow = get(operator_url + "api/1.3/slr/account/2/service/"+service_id,
                   headers={"Api-Key-User": user_key["Api-Key-User"]})
    #print(slr_flow.history)
    print("We made a request to:", slr_flow.history[0].url)
    print("It returned us url:", slr_flow.url)
    print(slr_flow.url, slr_flow.reason, slr_flow.status_code, slr_flow.text)

    print("Extracting parameters from the url...")
    params = slr_flow.url.split("/")[-1].split("?")[-1].split("&")
    params_dict = {}
    for item in params:  # This is done bit funny to avoid losing paddings from return_url
        key = item.split("=")[0]
        value = item.split("{}{}".format(key, "="))[1]
        params_dict[key] = value
    print(json.dumps(params_dict, indent=2))
    print("Adding Debug Credentials to the data for posting..")
    params_dict["Email"] = "Matti"
    params_dict["Password"] = "Uusio"


    print("POSTing the data to the Service Mockup Login (Simulating filling the form and hitting Submit")
    result = post(slr_flow.url.split("?")[0], json=params_dict, auth=(params_dict["Email"], params_dict["Password"""]))
    print(result.url, result.reason, result.status_code, result.text)
    print("Parsing response JSON from query parameters..")
    base = result.url.split("results=")[1]
    base = decode(str(base))
    print("Result decoded to: \n{}".format(base))
    decoded_json = json.loads(base)

    # if not slr_flow.ok:
    #     print("Creation of first SLR failed with status ({}) reason ({}) and the following content:\n{}".format(
    #         slr_flow.status_code,
    #         slr_flow.reason,
    #         json.dumps(json.loads(slr_flow.content), indent=2)
    #     ))
    #     raise Exception("SLR flow failed.")
    if not result.ok:
        print(result.url, result.reason, result.status_code, result.text)
    if not slr_flow.ok:
        print(slr_flow.url, slr_flow.reason, slr_flow.status_code, slr_flow.text)
    return decoded_json

def remove_slr(operatorl_url, user_key, slr_id, service_id):
    print("\n#### REMOVE SERVICE LINK ####")
    print("Removing SLR: {}".format(slr_id))
    result = delete("{}api/1.3/slr/account/2/service/{}/slr/{}".format(operatorl_url, service_id, slr_id),
                    headers={"Api-Key-User": user_key["Api-Key-User"]})
    print(result.url, result.reason, result.status_code, result.text)
    return result.text
# TODO: Refactor and return something.
# Gives a Consent for these Services by sending a Consent form as JSON-payload to Operator backend.
# Should print "201 Created" if the Consent was executed succesfully.
def give_consent(operator_url, sink_id, source_id, user_key):

    print("\n##### GIVE CONSENT #####")

    # This format needs to be specified, even if done with url params instead.
    ids = {"sink": sink_id, "source": source_id}

    print("\n###### 1.FETCH CONSENT FORM ######")
    req = get(operator_url + "api/1.3/cr/consent_form/account/2?sink={}&source={}".format(sink_id, source_id))
    if not req.ok:
        print("Fetching consent form consent failed with status ({}) reason ({}) and the following content:\n{}".format(
            req.status_code,
            req.reason,
            json.dumps(json.loads(req.content), indent=2)
        ))
        raise Exception("Consent flow failed.")

    print("\n###### 2.SEND CONSENT FORM ######")
    print(req.url, req.reason, req.status_code, req.text)
    js = json.loads(req.text)
    req = post(operator_url + "api/1.3/cr/consent_form/account/2", json=js,
               headers={"Api-Key-User": user_key["Api-Key-User"]})
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
    return js["source"]["rs_id"]

def make_data_request(service_url, rs_id):
    wait_time = 5
    print("\n##### Make_data_request #####")
    print("\n##### Waiting {} seconds for previous actions to complete #####".format(wait_time))
    time.sleep(wait_time)
    req = get(service_url + "api/1.3/sink_flow/debug_dc/{}".format(rs_id))
    if not req.ok:
        print("Debug Data request failed with status ({}) reason ({}) and the following content:\n{}".format(
            req.status_code,
            req.reason,
            json.dumps(json.loads(req.content), indent=2)
        ))
        raise Exception("Debug Data flow failed.")

    print(req.url, req.reason, req.status_code)
    print("\n")
    print(json.dumps(json.loads(json.loads(req.content)), indent=2))

    print("\n\n")
    return

if __name__ == '__main__':

    # Parse command line arguments
    parser = argparse.ArgumentParser()

    # Urls
    help_string_account_url = \
        "URL to Account. Defaults to 'http://localhost:8080'. \
        NOTE: Throws an error if run for second time as you cannot\
        create more accounts with same unique usernames.\
        (Will be fixed in later releases.)"
    parser.add_argument("--account_url",
                        help=help_string_account_url,
                        type=str,
                        default="http://localhost:8080/account/api/v1.3/",
                        required=False)

    help_string_operator_url = \
        "URL to Operator backend. Defaults to 'http://localhost:5000/'."
    parser.add_argument("--operator_url",
                        help=help_string_operator_url,
                        type=str,
                        default="http://localhost:5000/",
                        required=False)

    help_string_service_url = \
        "URL to Sink backend. Defaults to 'http://localhost:7001/'."
    parser.add_argument("--service_url",
                        help=help_string_service_url,
                        type=str,
                        default="http://localhost:7001/",
                        required=False)


    # Skips
    help_string_skip_init = \
        "Should account init be skipped. Init is done by default. Specify this flag to skip init."
    parser.add_argument("--skip_init",
                        help=help_string_skip_init,
                        action="store_true",
                        required=False)

    help_string_skip_slr = \
        "Should slr creation be skipped. SLR flow is done by default. Specify this flag to skip it."
    parser.add_argument("--skip_slr",
                        help=help_string_skip_slr,
                        action="store_true",
                        required=False)

    help_string_slr_removal = \
        "Should slr be removed after creation. If consent flow is done this is done after it."
    parser.add_argument("--remove_slr",
                        help=help_string_slr_removal,
                        action="store_true",
                        required=False)

    help_string_skip_consent = \
        "Should consent flow be skipped. It is done by default. Specify this flag to skip it."
    parser.add_argument("--skip_consent",
                        help=help_string_skip_consent,
                        action="store_true",
                        required=False)


    help_string_skip_data = \
        "Should data flow be skipped. It is done by default. Specify this flag to skip it."
    parser.add_argument("--skip_data",
                        help=help_string_skip_data,
                        action="store_true",
                        required=False)

    # IDs
    help_string_sink_id = \
        "ID of the Sink. \
        Check that this matches to what is specified in Service Registry. \
        Defaults to '{}'.".format(Service_ID_Sink)
    parser.add_argument("--sink_id",
                        help=help_string_sink_id,
                        type=str,
                        default=Service_ID_Sink,
                        required=False)

    help_string_source_id = \
        "ID of the Source. \
        Check that this matches to what is specified in Service Registry. \
        Defaults to '{}'.".format(Service_ID_Source)
    parser.add_argument("--source_id",
                        help=help_string_source_id,
                        type=str,
                        default=Service_ID_Source,
                        required=False)

#     exclusive_grp = parser.add_mutually_exclusive_group()
#     exclusive_grp.add_argument('--skip_init', action='store_true', dest='foo', help='skip init')
#     exclusive_grp.add_argument('--no-foo', action='store_false', dest='foo', help='do not do foo')

    args = parser.parse_args()

#     print 'Starting program', 'with' if args.foo else 'without', 'foo'
#     print 'Starting program', 'with' if args.no_foo else 'without', 'no_foo'

    # Just for user to see the given input
    print(args.account_url)
    print(args.operator_url)
    print(args.skip_init)
    print(args.sink_id)
    print(args.source_id)

    if not args.skip_init:
        # Do not skip init
        user_key = initialize(args.account_url)

    # SLR
    if not args.skip_slr:
        slr_1 = create_service_link(args.operator_url, args.sink_id, user_key)
        slr_2 = create_service_link(args.operator_url, args.source_id, user_key)

    # Consent
    if not args.skip_consent:
        rs_id = give_consent(args.operator_url, args.sink_id, args.source_id, user_key)

        # Debug Data Flow
        if not args.skip_data:
            make_data_request(args.service_url, rs_id)

    if args.remove_slr:
        print("Sleeping 5 seconds before removing SLR to allow possible CR flow to finish.")
        time.sleep(5)
        result = remove_slr(args.operator_url, user_key, slr_1["data"]["slr"]["id"], args.sink_id)
        pass
