# -*- coding: utf-8 -*-
import importlib
import logging
import pkgutil
import time
from base64 import urlsafe_b64decode as decode
from sqlite3 import IntegrityError

from flask import Blueprint
from flask_restful import Api

import db_handler as db_handler
from jwcrypto import jwt, jwk
from json import dumps, dump, load
from uuid import uuid4 as guid
from requests import get, post, patch
from json import loads
from core import DetailedHTTPException
import collections

# Logging
debug_log = logging.getLogger("debug")


# def read_key(path, password=None, ):
#     ##
#     # Read RSA key from PEM file and return JWK object of it.
#     ##
#     try:
#         from settings import cert_password_path
#         with open(cert_password_path, "r") as pw_file:
#             password = pw_file.readline()
#     except Exception as e:
#         print(e)
#         password = None
#         pass
#     if password is not None:  # Remove trailing line end if it exists
#         password = password.strip("\n")
#
#     from jwcrypto import jwk
#     from jwkest.jwk import RSAKey
#     with open(path, "r") as f:
#         pem_data = f.read()
#     try:
#         # Note import_rsa_key is importKey from CryptoDome
#         rsajwk = RSAKey(key=import_rsa_key(pem_data, passphrase=password), use='sig')
#
#     except ValueError as e:
#         while True:
#             pw = input("Please enter password for PEM file: ")
#             try:
#                 # Note import_rsa_key is importKey from CryptoDome
#                 rsajwk = RSAKey(key=import_rsa_key(pem_data, passphrase=pw), use='sig')
#                 save_pw = bool(str(raw_input("Should the password be saved?(True/False): ")).capitalize())
#                 if save_pw:
#                     with open("./cert_pw", "w+") as pw_file:
#                         pw_file.write(pw)
#                 break
#
#             except Exception as e:
#                 print(repr(e))
#                 print("Password may have been incorrect. Try again or terminate.")
#
#     jwssa = jwk.JWK(**rsajwk.to_dict())
#     return jwssa


def register_blueprints(app, package_name, package_path):
    """Register all Blueprint instances on the specified Flask application found
    in all modules for the specified package.
    :param app: the Flask application
    :param package_name: the package name
    :param package_path: the package path
    """
    rv = []
    apis = []
    for _, name, _ in pkgutil.iter_modules(package_path):
        m = importlib.import_module('%s.%s' % (package_name, name))
        for item in dir(m):
            item = getattr(m, item)
            if isinstance(item, Blueprint):
                app.register_blueprint(item)
            rv.append(item)
            if isinstance(item, Api):
                apis.append(item)
    return rv, apis

def get_am(current_app, headers):
    debug_log.info("Creating AccountManagerHandler, got headers:\n{}".format(headers))
    am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
    am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
    am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
    timeout = current_app.config["TIMEOUT"]

    return AccountManagerHandler(am_url, am_user, am_password, timeout, headers=headers)

class AccountManagerHandler:


    def __init__(self, account_management_url,
                 account_management_username,
                 account_management_password,
                 timeout,
                 headers):
        self.headers = headers
        self.username = account_management_username
        self.password = account_management_password  # possibly we don't need this here, does it matter?
        self.url = account_management_url
        self.user_key = None
        self.account_id = None
        self.timeout = timeout
        self.endpoint = {
            "key_sdk":          "account/api/v1.3/internal/auth/sdk/",
            "verify_user":      "account/api/v1.3/internal/auth/sdk/account/{account_id}/info/",
            "init_slr_sink":    "account/api/v1.3/internal/accounts/{account_id}/servicelinks/init/sink/",
            "init_slr_source":  "account/api/v1.3/internal/accounts/{account_id}/servicelinks/init/source/",
            "surrogate":        "api/account/{account_id}/service/{service_id}/surrogate/",  # Changed
            "sign_slr":         "account/api/v1.3/internal/accounts/{account_id}/servicelinks/{link_id}/",
            "verify_slr":       "account/api/v1.3/internal/accounts/{account_id}/servicelinks/{link_id}/store/",
            "fetch_slr":        "account/api/v1.3/internal/accounts/{account_id}/servicelinks/{link_id}/",
            "fetch_slrs":       "account/api/v1.3/internal/accounts/{account_id}/servicelinks/",
            "store_slr_change": "account/api/v1.3/internal/accounts/{account_id}/servicelinks/{link_id}/statuses/",
            "slr_status":       "account/api/v1.3/internal/accounts/{account_id}/servicelinks/{link_id}/statuses/last/",
            "sign_consent":     "api/account/consent/sign/",
            "services_slr":     "account/api/v1.3/internal/services/{service_id}/servicelinks?account_id={account_id}",
            "consent":          "account/api/v1.3/internal/accounts/{account_id}/servicelinks/{source_slr_id}/{sink_slr_id}/consents/",
            "fetch_consents":   "account/api/v1.3/internal/accounts/{account_id}/servicelinks/{link_id}/consents/",
            "auth_token":       "account/api/v1.3/internal/consents/{sink_cr_id}/authorisationtoken/",
            "last_csr":         "account/api/v1.3/internal/accounts/{account_id}/servicelinks/{link_id}/consents/{consent_id}/statuses/last/",
            "new_csr":          "account/api/v1.3/internal/accounts/{account_id}/consents/{cr_id}/statuses/"}  # Works as path to GET missing csr and POST new ones



        req = get(self.url + self.endpoint["key_sdk"], auth=(self.username, self.password), timeout=timeout)
        # check if the request for token succeeded
        debug_log.debug("{}  {}  {}".format(req.status_code, req.reason, req.text))
        if req.ok:
            self.token = loads(req.text)["Api-Key-Sdk"]
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Getting account management token failed.",
                                                "content": req.content},
                                        title=req.reason)

            # Here could be some code to setup where AccountManager is located etc, get these from ServiceRegistry?

    def url_constructor(self, endpoint="", replace=("", "")):
        if len(replace[1]) > 0:
            url = self.url + self.endpoint[endpoint].replace(replace[0], replace[1])
            debug_log.debug("Constructed url: ".format(url))
            return url
        else:
            url = self.url + self.endpoint[endpoint]
            debug_log.debug("Constructed url: ".format(url))
            return url

    def verify_user_key(self, account_id, user_key=None):
        try:
            if user_key is None:
                user_key = self.headers["Api-Key-User"]
            url = self.url_constructor("verify_user", ("{account_id}", account_id))
            query = get(url, headers={"Api-Key-Sdk": self.token, "Api-Key-User": user_key}, timeout=self.timeout)

            if query.ok:
                debug_log.debug("User key verified successfully!")
                self.user_key = user_key
                self.account_id = account_id
                return True
            else:
                debug_log.info("User key couldn't be verified.")
                raise DetailedHTTPException(status=403,
                                            detail={"msg": "Couldn't authenticate to account with given key."},
                                            title="Forbidden, invalid or expired auth key.")
        except KeyError as e:
            debug_log.debug("Couldn't find user key from headers.")
            debug_log.exception(e)
            raise e

    def init_slr(self, code, pop_key=None):
        debug_log.debug("")
        def get_link_id():
            return str(guid())

        template = {
            "code": code,
            "data": {
                "attributes": {
                    "slr_id": None,
                }
            }
        }

        def init(link_id, template, retry=True):
            template["data"]["attributes"]["slr_id"] = link_id
            if pop_key is None:
                debug_log.debug(
                    "Filled template for init Source SLR at Account:\n  {}".format(dumps(template, indent=2)))
                url = self.url_constructor("init_slr_source", ("{account_id}", self.account_id))
            else:
                debug_log.info("Pop key is type {} and contains: \n{}".format(type(pop_key), pop_key))
                template["data"]["attributes"]["pop_key"] = pop_key
                debug_log.debug("Filled template for init Sink SLR at Account:\n  {}".format(dumps(template, indent=2)))
                url = self.url_constructor("init_slr_sink", ("{account_id}", self.account_id))
            query = post(url,
                         headers={"Api-Key-Sdk": self.token, "Api-Key-User": self.user_key},
                         timeout=self.timeout,
                         json=template)
            if query.status_code == 201:
                return link_id
            elif query.status_code == 409:
                debug_log.info("Collision, generating new link_id and retrying.")
                if retry:
                    return init(link_id=get_link_id(), template=template, retry=False)
                raise DetailedHTTPException(title="Couldn't generate unique Service Link ID",
                                            status=500)
            else:
                raise DetailedHTTPException(title="Error Occurred while storing slr_id",
                                            status=500)

        return init(get_link_id(), template)

    def get_slr_with_service_id(self, service_id, account_id):
        if self.account_id != account_id:  # Someone tries to get slr that doesn't belong to them.
            debug_log.error("Account ID mismatch.\n"
                            "ID '{}' doesn't match with verified id '{}'".format(account_id, self.account_id))
            raise DetailedHTTPException(status=404,
                                        detail={"msg": "Couldn't find SLR with given id."},
                                        title="Not Found")

        debug_log.info("Fetching SLR's for service id '{}' that belongs to account '{}'".format(service_id, account_id))
        slr = get(self.url + self.endpoint["services_slr"]
                  .replace("{account_id}", account_id)
                  .replace("{service_id}", service_id),
                  headers={"Api-Key-Sdk": self.token, "Api-Key-User": self.user_key},
                  timeout=self.timeout,
                  )
        debug_log.info("Request resulted in status {} and content:\n {}".format(slr.status_code, slr.text))
        if slr.ok:
            return loads(slr.text)
        elif slr.status_code == 404:
            debug_log.info("No slr's found, returning empty data list.")
            return {"data": []}
        else:
            raise DetailedHTTPException(status=slr.status_code,
                                        detail={"msg": slr.text},
                                        title=slr.reason)

    def check_for_existing_slr(self, service_id, account_id):
        debug_log.info("Checking if account '{}' has existing Active SLR's for service '{}'"
                       .format(account_id, service_id))
        existing_slrs = self.get_slr_with_service_id(service_id, account_id)
        for slr in existing_slrs["data"]:
            slr_id = slr["id"]
            last_ssr = self.get_last_slr_status(slr_id)
            last_ssr_payload = base_token_tool.decode_payload(last_ssr["data"]["attributes"]["payload"])
            if last_ssr_payload["sl_status"] == "Active":
                raise DetailedHTTPException(status=409,
                                        detail={"msg": "an Active SLR exist for this user and service, "
                                                       "please disable existing SLR before creating new one."},
                                        title="Existing Active SLR found.")


    def check_existing_consent(self, service_id_sink, service_id_source, account_id):

        debug_log.info("Checking if account '{}' has existing CR's for service's '{}' and '{}'"
                       .format(account_id, service_id_sink, service_id_source))
        existing_slrs = self.get_slr_with_service_id(service_id_sink, account_id)
        for slr in existing_slrs["data"]:
            # Get all slr's for sink
            slr_id = slr["id"]
            last_ssr = self.get_last_slr_status(slr_id)
            last_ssr_payload = base_token_tool.decode_payload(last_ssr["data"]["attributes"]["payload"])
            # We don't care about disabled SLR's
            if last_ssr_payload["sl_status"] == "Active":
                # For each active SLR fetch all cr's, check that cr's subject field and compare it to source.
                crs = self.get_crs(slr_id, account_id)["data"]
                for consent in crs:
                    debug_log.debug("Fetched consent: \n{}".format(consent))
                    cr_payload = base_token_tool.decode_payload(consent["attributes"]["payload"])

                    # Fetch last csr for the source set in role_specific_part of sink cr:
                    source_csr = self.get_last_csr_with_cr_id(cr_payload["role_specific_part"]["source_cr_id"],
                                                              account_id)

                    # Pairs are supposed to be in sync, so if this is active, so is the sink one.
                    if source_csr["consent_status"] == "Active":
                        raise DetailedHTTPException(status=409,
                                        detail={"msg": "an Active CR exist for this user and selected services, "
                                                       "please disable existing CR before creating new one."},
                                        title="Existing Active CR found.")


    def get_slr(self, slr_id, account_id):

        if self.account_id != account_id:  # Someone tries to get slr that doesn't belong to them.
            debug_log.error("Account ID mismatch.\n"
                            "ID '{}' doesn't match with verified id '{}'".format(account_id, self.account_id))
            raise DetailedHTTPException(status=404,
                                        detail={"msg": "Couldn't find SLR with given id."},
                                        title="Not Found")

        debug_log.info("Fetching SLR for link id '{}' that belongs to account '{}'".format(slr_id, account_id))
        slr = get(self.url + self.endpoint["fetch_slr"]
                  .replace("{account_id}", account_id)
                  .replace("{link_id}", slr_id),
                  headers={"Api-Key-Sdk": self.token, "Api-Key-User": self.user_key},
                  timeout=self.timeout,
                  )
        debug_log.info("Request resulted in status {} and content:\n {}".format(slr.status_code, slr.text))
        if slr.ok:
            return loads(slr.text)
        else:
            raise DetailedHTTPException(status=404,
                                        detail={"msg": "Couldn't find SLR with given id."},
                                        title="Not Found")

    def get_slrs(self, account_id):

        if self.account_id != account_id:  # Someone tries to get slr that doesn't belong to them.
            debug_log.error("Account ID mismatch.\n"
                            "ID '{}' doesn't match with verified id '{}'".format(account_id, self.account_id))
            raise DetailedHTTPException(status=404,
                                        detail={"msg": "Couldn't find SLR with given id."},
                                        title="Not Found")

        debug_log.info("Fetching SLRs that belongs to account '{}'".format(account_id))
        slrs = get(self.url + self.endpoint["fetch_slrs"]
                  .replace("{account_id}", account_id),
                  headers={"Api-Key-Sdk": self.token, "Api-Key-User": self.user_key},
                  timeout=self.timeout,
                  )
        debug_log.info("Request resulted in status {} and content:\n {}".format(slrs.status_code, slrs.text))
        if slrs.ok:
            return loads(slrs.text)
        else:
            raise DetailedHTTPException(status=404,
                                        detail={"msg": "Couldn't find SLRs for account"},
                                        title="Not Found")

    def get_surrogate_and_slr_id(self, account_id, service_id):
        debug_log.info("Fetching surrogate_id and slr_id for account '{}' and service '{}'"
                       .format(account_id, service_id))
        slrs = self.get_slrs(account_id=account_id)

        for slr in slrs["data"]:
            decoded_payload = base_token_tool.decode_payload(slr["attributes"]["payload"])
            if service_id == decoded_payload["service_id"]:
                return slr["id"], decoded_payload["surrogate_id"]
        raise DetailedHTTPException(status=404,
                                    detail={"msg": "Couldn't find SLR for given service."},
                                    title="Not Found")

    def get_last_slr_status(self, slr_id):
        debug_log.info("Fetching last SSR for id '{}'".format(slr_id))
        req = get(self.url+self.endpoint["slr_status"]
                  .replace("{account_id}", self.account_id)
                  .replace("{link_id}", slr_id),
                  headers={'Api-Key-Sdk': self.token, "Api-Key-User": self.user_key}, timeout=self.timeout)
        debug_log.debug("{}  {}  {}  {}".format(req.status_code, req.reason, req.text, req.content))
        if req.ok:
            return loads(req.text)

    def get_crs(self, slr_id, account_id, pairs=False):

        if self.account_id != account_id:  # Someone tries to get slr that doesn't belong to them.
            debug_log.error("Account ID mismatch.\n"
                            "ID '{}' doesn't match with verified id '{}'".format(account_id, self.account_id))
            raise DetailedHTTPException(status=404,
                                        detail={"msg": "Couldn't find SLR with given id."},
                                        title="Not Found")
        debug_log.info("Fetching CR's for link id '{}' that belongs to account '{}'".format(slr_id, account_id))
        query = ""
        if pairs:
            query = "?get_consent_pair=true"

        consents = get(self.url + self.endpoint["fetch_consents"]
                       .replace("{account_id}", account_id)
                       .replace("{link_id}", slr_id)+query,
                       headers={"Api-Key-Sdk": self.token, "Api-Key-User": self.user_key},
                       timeout=self.timeout,
                       )
        debug_log.info("Request resulted in status {} and content:\n {}".format(consents.status_code, consents.text))
        if consents.ok:
            return loads(consents.text)
        else:
            if consents.status_code == 404:
                debug_log.info("Couldn't find consents for the SLR.")
                return {"data":[]}
            debug_log.info("Fetching consents failed with: {}"
                           .format([consents.status_code, consents.reason, consents.text]))
            raise DetailedHTTPException(status=404,
                                        detail={"msg": "Couldn't find SLR with given id."},
                                        title="Not Found")

    def get_cr_pair(self, cr_id):
        debug_log.info("\nFetching CR pair for CR '{}'".format(cr_id))
        pass

    def get_AuthTokenInfo(self, cr_id):
        req = get(self.url + self.endpoint["auth_token"]
                  .replace("{sink_cr_id}", cr_id),
                  headers={'Api-Key-Sdk': self.token}, timeout=self.timeout)
        if req.ok:
            templ = loads(req.text)
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Getting AuthToken info from account management failed.",
                                                "content": req.content},
                                        title=req.reason)
        return templ

    def get_last_csr(self, cr_id, link_id):
        endpoint_url = self.url + self.endpoint["last_csr"]\
            .replace("{consent_id}", cr_id)\
            .replace("{account_id}", self.account_id)\
            .replace("{link_id}", link_id)
        debug_log.debug("" + endpoint_url)

        req = get(endpoint_url,
                  headers={'Api-Key-Sdk': self.token,
                           "Api-Key-User": self.user_key},
                  timeout=self.timeout)
        debug_log.debug("{}  {}  {}  {}".format(req.status_code, req.reason, req.text, req.content))
        if req.ok:
            templ = loads(req.text)
            payload = base_token_tool.decode_payload(templ["data"]["attributes"]["payload"])
            debug_log.info("Got CSR payload from account:\n{}".format(dumps(payload, indent=2)))
            csr_id = payload["record_id"]
            return payload
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Getting last csr from account management failed.",
                                                "content": req.content},
                                        title=req.reason)


    def get_last_csr_with_cr_id(self, cr_id, account_id):
        endpoint_url = self.url + self.endpoint["new_csr"].replace("{cr_id}", cr_id).replace("{account_id}", self.account_id)+"last"
        debug_log.debug("" + endpoint_url)

        req = get(endpoint_url,
                  headers={'Api-Key-Sdk': self.token,
                           "Api-Key-User": self.user_key},
                  timeout=self.timeout)
        debug_log.debug("{}  {}  {}  {}".format(req.status_code, req.reason, req.text, req.content))
        if req.ok:
            templ = loads(req.text)
            payload = base_token_tool.decode_payload(templ["data"]["attributes"]["payload"])
            debug_log.info("Got CSR payload from account:\n{}".format(dumps(payload, indent=2)))
            csr_id = payload["record_id"]
            return payload
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Getting last csr from account management failed.",
                                                "content": req.content},
                                        title=req.reason)


    def create_new_csr(self, cr_id, payload): # TODO: cr_id is in payload, no need to have it passed as argument.
        debug_log.info("Issuing new Consent Status Record.")
        endpoint_url = self.url + self.endpoint["new_csr"]\
            .replace("{cr_id}", cr_id)\
            .replace("{account_id}", self.account_id)
        debug_log.info("POST: {}".format(endpoint_url))
        payload = {"data": {"attributes": payload, "type": "consent_status_record"}}
        req = post(endpoint_url, json=payload,
                   headers={'Api-Key-Sdk': self.token,
                            "Api-Key-User": self.user_key},
                   timeout=self.timeout)
        debug_log.info("{}  {}  {}  {}".format(req.status_code, req.reason, req.text, req.content))
        if req.ok:
            templ = loads(req.text)
            #tool = SLR_tool()
            #payload = tool.decode_payload(templ["data"]["attributes"]["csr"]["payload"])
            debug_log.info("Created CSR:\n{}".format(dumps(templ, indent=2)))
            #csr_id = payload["record_id"]

            return templ
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Creating new csr at account management failed.",
                                                "content": req.content},
                                        title=req.reason)

    def get_missing_csr(self, cr_id, csr_id):
        debug_log.debug("Fetching missing CSR's")
        endpoint_url = self.url + self.endpoint["new_csr"].replace("{cr_id}", cr_id)
        debug_log.info("GET: {}".format(endpoint_url))
        payload = {"csr_id": csr_id}
        req = get(endpoint_url, params=payload,
                  headers={'Api-Key-Sdk': self.token,
                           "Api-Key-User": self.user_key},
                   timeout=self.timeout)
        if req.ok:
            templ = loads(req.text)
            #tool = SLR_tool()
            #payload = tool.decode_payload(templ["data"]["attributes"]["csr"]["payload"])
            debug_log.info("Fetched missing CSR:\n{}".format(dumps(templ, indent=2)))
            #csr_id = payload["record_id"]

            return {"missing_csr": templ}
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Creating new csr at account management failed.",
                                                "content": req.content},
                                        title=req.reason)

    def sign_slr(self, template, account_id):
        req = patch(self.url + self.endpoint["sign_slr"]
                    .replace("{account_id}", self.account_id)
                    .replace("{link_id}", template["data"]["attributes"]["link_id"]), json=template,
                    headers={'Api-Key-Sdk': self.token, "Api-Key-User": self.user_key}, timeout=self.timeout)
        debug_log.debug("API token: {}".format(self.token))
        debug_log.debug("{}  {}  {}  {}".format(req.status_code, req.reason, req.text, req.content))
        if req.ok:
            templ = loads(req.text)
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Getting surrogate_id from account management failed.",
                                                "content": loads(req.text)},
                                        title=req.reason)

        debug_log.debug(templ)
        return templ

    def create_ssr(self, surrogate_id, slr_id, sl_status, prev_record_id):
        allowed_statuses = ["Active", "Removed"]
        if sl_status not in allowed_statuses:
            raise TypeError("sl_status must be of type {}".format(allowed_statuses))
        if prev_record_id is None:
            raise TypeError("prev_record_id must be defined.")

        payload = {
            "data": {
                "type": "ServiceLinkStatusRecord",
                "attributes": {
                    "version": "1.3",
                    "surrogate_id": surrogate_id,
                    "record_id": str(guid()),
                    "account_id": self.account_id,
                    "slr_id": slr_id,
                    "sl_status": sl_status,
                    "iat": int(time.time()),
                    "prev_record_id": prev_record_id
                },
            }
        }
        req = post(self.url+self.endpoint["store_slr_change"]
                   .replace("{account_id}", self.account_id)
                   .replace("{link_id}", slr_id),
                   json=payload,
                   headers={'Api-Key-Sdk': self.token, "Api-Key-User": self.user_key}, timeout=self.timeout)
        debug_log.debug("{}  {}  {}  {}".format(req.status_code, req.reason, req.text, req.content))
        if req.ok:
            return loads(req.text)
        else:
            raise DetailedHTTPException(title="An Error Has occured on the server. Try again later.",
                                        status=500,
                                        detail={"msg": "Failed SLR status change."})

    def verify_slr(self, payload, code, slr, account_id):
        templa = {
            "code": code,
            "data": {
                "slr": {
                    "attributes": slr,
                    "id": payload["link_id"],
                    "type": "ServiceLinkRecord",
                },
                "ssr": {
                    "attributes": {
                        "version": "1.3",
                        "surrogate_id": payload["surrogate_id"],
                        "record_id": str(guid()),
                        "account_id": account_id,
                        "slr_id": payload["link_id"],
                        "sl_status": "Active",
                        "iat": int(time.time()),
                        "prev_record_id": "NULL"
                    },
                    "type": "ServiceLinkStatusRecord"
                },
            }
        }
        debug_log.info("Template sent to Account Manager:")
        debug_log.info(dumps(templa, indent=2))
        req = post(self.url + self.endpoint["verify_slr"]
                   .replace("{account_id}", account_id)
                   .replace("{link_id}", payload["link_id"]), json=templa,
                   headers={'Api-Key-Sdk': self.token, "Api-Key-User": self.user_key}, timeout=self.timeout)
        return req

    def signAndstore(self, sink_cr, sink_csr, source_cr, source_csr, account_id):
        structure = {"sink": {
            "cr": sink_cr["cr"],
            "csr": sink_csr
        },
            "source": {
                "cr": source_cr["cr"],
                "csr": source_csr
            }
        }

        template = {
            "data": {
                "source": {
                    "consent_record_payload": {
                        "type": "ConsentRecord",
                        "attributes": source_cr["cr"]
                    },
                    "consent_status_record_payload": {
                        "type": "ConsentStatusRecord",
                        "attributes": source_csr,
                    }
                },
                "sink": {
                    "consent_record_payload": {
                        "type": "ConsentRecord",
                        "attributes": sink_cr["cr"],
                    },
                    "consent_status_record_payload": {
                        "type": "ConsentStatusRecord",
                        "attributes": sink_csr,
                    },
                },
            },
        }

        slr_id_sink = template["data"]["sink"]["consent_record_payload"]["attributes"]["common_part"]["slr_id"]
        slr_id_source = template["data"]["source"]["consent_record_payload"]["attributes"]["common_part"]["slr_id"]
        # print(type(slr_id_source), type(slr_id_sink), account_id)
        debug_log.debug(dumps(template, indent=2))
        req = post(self.url + self.endpoint["consent"].replace("{account_id}", account_id)
                   .replace("{source_slr_id}", slr_id_source).
                   replace("{sink_slr_id}", slr_id_sink),
                   json=template,
                   headers={'Api-Key-Sdk': self.token, "Api-Key-User": self.user_key},
                   timeout=self.timeout)
        debug_log.debug("{}  {}  {}  {}".format(req.status_code, req.reason, req.text, req.content))
        if req.ok:
            debug_log.debug(dumps(loads(req.text), indent=2))
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Getting surrogate_id from account management failed.",
                                                "content": loads(req.text)},
                                        title=req.reason)

        return loads(req.text)

class ServiceRegistryHandler:
    def __init__(self, domain, endpoint):
        # self.registry_url = "http://178.62.229.148:8081"+"/api/v1/services/"
        self.registry_url = domain + endpoint

    def getService(self, service_id):
        try:
            debug_log.info("Making request GET {}{}".format(self.registry_url, service_id))
            req = get(self.registry_url+service_id)
            service = req.json()
            debug_log.info(service)
            # TODO: This check is made purely for the reason jsonserver used for developing doesn't wrap json in []
            # Do we need it in deployment?
            if isinstance(service, list):
                service = service[0]
        except Exception as e:
            debug_log.exception(e)
            raise e
        return service

    def getService_url(self, service_id):
        debug_log.info("getService_url got service id {} of type {} as parameter.".format(service_id, type(service_id)))
        if isinstance(service_id, unicode):
            service_id = service_id.encode()
        try:
            service = get(self.registry_url+service_id).json()
            # TODO: This check is made purely for the reason jsonserver used for developing doesn't wrap json in []
            # Do we need it in deployment?
            if isinstance(service, list):
                service = service[0]
        except Exception as e:
            debug_log.exception(e)
            raise e
        url = service["serviceInstance"][0]["domain"]
        return url


class Helpers:
    def __init__(self, app_config):
        self.host = app_config["MYSQL_HOST"]
        self.cert_key_path = app_config["CERT_KEY_PATH"]
        self.keysize = app_config["KEYSIZE"]
        self.keytype = app_config["KEYTYPE"]
        self.user = app_config["MYSQL_USER"]
        self.passwd = app_config["MYSQL_PASSWORD"]
        self.db = app_config["MYSQL_DB"]
        self.port = app_config["MYSQL_PORT"]
        self.operator_id = app_config["UID"]
        self.not_after_interval = app_config["NOT_AFTER_INTERVAL"]
        self.service_registry_search_domain = app_config["SERVICE_REGISTRY_SEARCH_DOMAIN"]
        self.service_registry_search_endpoint = app_config["SERVICE_REGISTRY_SEARCH_ENDPOINT"]


    # def header_fix(self, malformed_dictionary):  # We do not check if its malformed, we expect it to be.
    #     if malformed_dictionary.get("signature", False):
    #         malformed_dictionary["header"] = loads(malformed_dictionary["header"])
    #         return malformed_dictionary
    #     elif malformed_dictionary.get("signatures", False):
    #         sigs = malformed_dictionary["signatures"]
    #         for signature in sigs:
    #             if isinstance(signature["header"], str):
    #                 signature["header"] = loads(signature["header"])
    #         return malformed_dictionary
    #     raise ValueError("Received dictionary was not expected type.")

    def get_key(self):
        keysize = self.keysize
        cert_key_path = self.cert_key_path
        if self.keytype == "RSA":
            gen3 = {"generate": "RSA", "size": self.keysize, "kid": self.operator_id}
            protti = {"alg": "RS256"}
        elif self.keytype == "EC256":
            gen3 = {"generate": "EC", "cvr": "P-256", "kid": self.operator_id}
            protti = {"alg": "ES256"}
        else:  # Defaulting to EC256
            gen3 = {"generate": "EC", "cvr": "P-256", "kid": self.operator_id}
            protti = {"alg": "ES256"}
        service_key = jwk.JWK(**gen3)
        try:
            with open(cert_key_path, "r") as cert_file:
                service_key2 = jwk.JWK(**loads(load(cert_file)))
                service_key = service_key2
        except Exception as e:
            debug_log.error(e)
            with open(cert_key_path, "w+") as cert_file:
                dump(service_key.export(), cert_file, indent=2)
        public_key = loads(service_key.export_public())
        full_key = loads(service_key.export())

        headeri = {"kid": self.operator_id, "jwk": public_key}
        return {"pub": public_key,
                "key": full_key,
                "prot": protti,
                "header": headeri}

    def validate_rs_id(self, rs_id):
        ##
        # Validate here the RS_ID
        ##
        return self.change_rs_id_status(rs_id, True)

    # TODO: This should return list, now returns single object. # Recheck validity
    def get_service_keys(self, surrogate_id):
        """

        """
        storage_rows = self.query_db_multiple("select * from service_keys_tbl where surrogate_id = %s;",
                                              (surrogate_id,))
        list_of_keys = []
        for item in storage_rows:
            list_of_keys.append(item[2])

        debug_log.info("Found keys:\n {}".format(list_of_keys))
        return list_of_keys


    # def get_slr(self, surrogate_id, service_id, service_key):
    #     service_keys = self.get_service_keys(surrogate_id)
    #     storage_row = self.query_db_multiple("select * from service_keys_tbl where surrogate_id = %s and kid = %s;",
    #                                          (surrogate_id, kid,), one=True)

    def delete_session(self, code):
        try:
            debug_log.info("Deleting session: {}".format(code))
            db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
            cursor = db.cursor()
            cursor.execute("DELETE FROM session_store WHERE code=%s ;", (code,))
            db.commit()
            cursor.close()
            debug_log.info("Session {} deleted.".format(code))
        except Exception as e:
            debug_log.info("Something went wrong while deleting session {}.".format(code))
            debug_log.exception(e)

    def get_service_key(self, surrogate_id, kid):
        """

        """
        storage_row = self.query_db_multiple("select * from service_keys_tbl where surrogate_id = %s and kid = %s;",
                                             (surrogate_id, kid,), one=True)
        # Third item in this tuple should be the key JSON {token_key: {}, pop_key:{}}
        key_json_from_db = loads(storage_row[2])

        return key_json_from_db

    def store_service_key_json(self, kid, surrogate_id, key_json, service_id):
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        try:
            cursor.execute("INSERT INTO service_keys_tbl (kid, surrogate_id, key_json, service_id) \
                VALUES (%s, %s, %s, %s);", (kid, surrogate_id, dumps(key_json), service_id))
            db.commit()
        except Exception as e:
            debug_log.exception(e)
            debug_log.debug("Apparently we have stored service keys for given surrogate_id '{}' and service '{}'\n"
                            "Updating existing keys."
                            .format(surrogate_id, service_id))
            cursor.execute("UPDATE service_keys_tbl SET key_json=%s WHERE kid=%s ;", (dumps(key_json), kid))
            db.commit()
        debug_log.info("Stored key_json({}) for surrogate_id({}) into DB".format(key_json, surrogate_id))
        cursor.close()

    def storeRS_ID(self, rs_id):
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        rs_id_status = False
        cursor.execute("INSERT INTO rs_id_tbl (rs_id, used) \
            VALUES (%s, %s)", (rs_id, rs_id_status))
        db.commit()
        debug_log.info("Stored RS_ID({}) into DB".format(rs_id))
        cursor.close()

    def change_rs_id_status(self, rs_id, status):
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        cursor.execute("select * from rs_id_tbl where rs_id=%s;", (rs_id,))
        result = cursor.fetchone()
        rs_id = result[0]
        used = result[1]
        debug_log.info(result)
        status_from_db = bool(used)
        status_is_unused = status_from_db is False
        if status_is_unused:
            cursor.execute("UPDATE rs_id_tbl SET used=%s WHERE rs_id=%s ;", (status, rs_id))
            db.commit()
            cursor.close()
            return True
        else:
            cursor.close()
            return False

    def store_session(self, DictionaryToStore):
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)

        for key in DictionaryToStore:
            debug_log.info(key)

            try:
                cursor.execute("INSERT INTO session_store (code,json) \
                    VALUES (%s, %s)", (key, dumps(DictionaryToStore[key])))
                db.commit()
            except IntegrityError as e:
                debug_log.info("")
                raise e
        db.close()

    def query_db(self, query, args=()):
        '''
        Simple queries to DB
        :param query: SQL query
        :param args: Arguments to inject into the query
        :return: Single hit for the given query
        '''

        result = self.query_db_multiple(query, args=args, one=True)
        if result is not None:
            debug_log.info("Made DB query: {}\nResult type: {}\nResult content: {}".format(query, type(result), result))
            return result[1]
        else:
            return None

    def query_db_multiple(self, query, args=(), one=False):
        '''
        Simple queries to DB
        :param query: SQL query
        :param args: Arguments to inject into the query
        :return: all hits for the given query
        '''
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        cur = cursor.execute(query, args)
        if one:
            try:
                result = cursor.fetchone()  # Returns tuple
                debug_log.info(result)
                if result is not None:
                    db.close()
                    debug_log.info("Made DB query: {}\n"
                                   "Result type: {}\n"
                                   "Result content: {}".format(query, type(result), result))
                    return result  # the tuple.
                else:
                    return None
            except Exception as e:
                debug_log.exception(e)
                debug_log.info(cur)
                db.close()
                return None
        else:
            try:
                result = cursor.fetchall()  # Returns tuple
                debug_log.info(result)
                if result is not None:
                    db.close()
                    debug_log.info("Made DB query: {}\n"
                                   "Result type: {}\n"
                                   "Result content: {}".format(query, type(result), result))
                    return result  # This should be list of tuples [(1,2,3), (3,4,5)...]
                else:
                    return None
            except Exception as e:
                debug_log.exception(e)
                debug_log.info(cur)
                db.close()
                return None

    def gen_rs_id(self, source_URI):
        ##
        # Something to check state here?
        # Also store RS_ID in DB around here.
        ##

        rs_id = "{}{}".format(source_URI.replace("http://", "").replace("https://", ""), str(guid()))
        self.storeRS_ID(rs_id)
        return rs_id

    def store_consent_form(self, consent_form):
        ##
        # Store POSTed consent form, this might be removed (read in the flow picture)
        ##
        return True

    def gen_cr_common(self, sur_id, rs_ID, slr_id, issued, not_before, not_after, subject_id, operator_id, role):
        ##
        # Return common part of CR
        # Some of these fields are filled in consent_form.py
        ##
        common_cr = {
            "version": "1.3",
            "cr_id": str(guid()),
            "surrogate_id": sur_id,
            "rs_id": rs_ID,
            "slr_id": slr_id,
            "iat": issued,
            "nbf": not_before,
            "exp": not_after,
            "operator": operator_id,
            "subject_id": subject_id,  # TODO: Should this really be in common_cr?
            "role": role
        }

        return common_cr

    def gen_cr_sink(self, common_CR, consent_form, ki_cr, source_cr_id):
        _rules = []
        common_CR["subject_id"] = consent_form["sink"]["service_id"]

        # This iters trough all datasets, iters though all purposes in those data sets, and add title to
        # _rules. It seems to be enough efficient for this purpose.
        # [[_rules.append(purpose["title"]) for purpose in dataset["purposes"]  # 2
        #   if purpose["selected"] == True or purpose["required"] == True]  # 3
        #  for dataset in consent_form["sink"]["dataset"]]  # 1
        for dataset in consent_form["sink"]["dataset"]:
            for purpose in dataset["purposes"]:
                _rules.append(purpose["title"])


        _rules = list(set(_rules))  # Remove duplicates
        _tmpl = {"cr": {
            "common_part": common_CR,
            "role_specific_part": {
                "source_cr_id": source_cr_id,
                "usage_rules": _rules
            },
            "consent_receipt_part": {"ki_cr": ki_cr},
            "extension_part": {"extensions": {}}
        }
        }

        return _tmpl

    def gen_cr_source(self, common_CR, consent_form, ki_cr,
                      sink_pop_key):
        common_CR["subject_id"] = consent_form["source"]["service_id"]
        rs_description = \
            {
                "rs_description": {
                    "resource_set":
                        {
                            "rs_id": consent_form["source"]["rs_id"],
                            "dataset": [
                                {
                                    "dataset_id": "String",
                                    "distribution_id": "String",
                                    "distribution_url": ""
                                }
                            ]
                        }

                }
            }
        common_CR.update(rs_description)
        _tmpl = {"cr": {
            "common_part": common_CR,
            "role_specific_part": {
                "pop_key": sink_pop_key,
                "token_issuer_key": self.get_key()["pub"],
            },
            "consent_receipt_part": {"ki_cr": ki_cr},
            "extension_part": {"extensions": {}}
        }
        }
        _tmpl["cr"]["common_part"]["rs_description"]["resource_set"]["dataset"] = []

        for dataset in consent_form["source"]["dataset"]:
            dt_tmp = {
                "dataset_id": dataset["dataset_id"],
                "distribution_id": dataset["distribution"]["distribution_id"],
                "distribution_url": dataset["distribution"]["access_url"]
            }
            _tmpl["cr"]["common_part"]["rs_description"]["resource_set"]["dataset"].append(dt_tmp)

        return _tmpl

    def Gen_ki_cr(self, everything):
        return {}

    def gen_csr(self, surrogate_id, consent_record_id, consent_status, previous_record_id):
        _tmpl = {
            "version": "1.3",
            "record_id": str(guid()),
            "surrogate_id": surrogate_id,
            "cr_id": consent_record_id,
            "consent_status": consent_status,  # "Active/Disabled/Withdrawn"
            "iat": int(time.time()),
            "prev_record_id": previous_record_id,
        }
        return _tmpl

    def gen_auth_token(self, auth_token_info):
        operator_key = jwk.JWK(**self.get_key()["key"])
        slr_tool = JWS_tool()
        slr_tool.slr = auth_token_info
        debug_log.debug(dumps(slr_tool.get_SLR_payload(), indent=2))
        debug_log.debug(dumps(slr_tool.get_CR_payload(), indent=2))
        # Claims
        srv_handler = ServiceRegistryHandler(self.service_registry_search_domain, self.service_registry_search_endpoint)
        payload = {"iss": self.operator_id,  # Operator ID,
                   "cnf": {"kid": slr_tool.get_source_cr_id()},
                   "aud": srv_handler.getService_url(slr_tool.get_source_service_id()),
                   "exp": int(time.time() + self.not_after_interval),
                   # datetime.fromtimestamp(time.time()+2592000).strftime("%Y-%m-%dT%H:%M:%S %Z"), # 30 days in seconds
                   # Experiation time of token on or after which token MUST NOT be accepted
                   "nbf": int(time.time()),
                   # datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S %Z"),  # The time before which token MUST NOT be accepted
                   "iat": int(time.time()),
                   # datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S %Z"),  # The time which the JWT was issued
                   "jti": str(guid()),  # JWT id claim provides a unique identifier for the JWT
                   "pi_id": slr_tool.get_source_cr_id(),  # Resource set id that was assigned in the linked Consent Record
                   }
        key = operator_key

        if self.keytype == "EC256":
            header = {"alg": "ES256"}  # TODO: get alg from same place get_key gets it.
        elif self.keytype == "RSA":
            header = {"alg": "RS256"}
        else:  # Defaulting to EC P-256
            header = {"alg": "ES256"}
        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(key)
        return token.serialize()

    def get_service_cr_endpoint(self, service_id):
        return "/api/1.3/cr/cr_management"

class base_token_tool:

    @staticmethod
    def decode_payload(payload):
        payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
        content = decode(payload.encode())
        payload = loads(content.decode("utf-8"))
        debug_log.info("Decoded payload is:")
        debug_log.info(payload)
        return payload


# Perhaps worth noting that we're using interal variabled and could be worth stop using them if possible.
def format_request(request):
    dicti = request.__dict__["environ"]
    msg_tuples = [("From", dicti["REMOTE_ADDR"]+":"+str(dicti["REMOTE_PORT"])),
                  ("To", request.url),
                  ("Type", request.method),
                  ("ContentType", dicti["CONTENT_TYPE"]),
                  ("ContentLength", dicti["CONTENT_LENGTH"]),
                  ("Flask Blueprint", request.blueprint),
                  ("Flask Arguments", request.view_args)
                  ]
    msg_tmpl = collections.OrderedDict(msg_tuples)
    js = request.get_json(silent=True)
    if js is not None:
        msg_tmpl["JSON"] = js

    req_form = request.form
    if len(req_form.keys()) > 0:
        msg_tmpl["FORM"] = req_form

    req_query = request.args
    if len(req_query.keys()) > 0:
        msg_tmpl["QUERY"] = req_query

    msg = dumps(msg_tmpl, indent=2)
    return msg


def format_response(response):
    response_dict = response.__dict__
    headers = {}
    resp_headers = response.headers
    for header in resp_headers.keys():
        headers[header] = resp_headers[header]

    msg_tuples = [
        ("Status", response.status),
        ("Status Code", response.status_code),
        ("Headers", headers)
    ]
    msg_tmpl = collections.OrderedDict(msg_tuples)
    data = response.get_data(as_text=True)
    try:
        data = loads(data)
    except Exception as e:
        pass
    msg_tmpl["Data"] = data
    msg = dumps(msg_tmpl, indent=2)
    return msg


from functools import wraps
from flask import request, make_response
from werkzeug.wrappers import Response
def api_logging(func):
    @wraps(func)
    def loggedfunc(*args, **kwargs):
        req_msg = format_request(request)
        debug_log.info(req_msg)

        resp = func(*args, **kwargs)
        debug_log.info(type(resp))
        debug_log.info(resp)

        # We know well how to handle Response objects
        if isinstance(resp, Response):
            resp_msg = format_response(resp)

        # Handle dict's
        elif isinstance(resp, dict):
            resp = make_response((dumps(resp), 200, {"Content-Type": "application/json"}))
            resp_msg = format_response(resp)

        # Handle Nonetype
        elif resp is None:
            resp = make_response(("", 200, {"Content-Type": "text/html"}))
            resp_msg = format_response(resp)

        # Handle tuples with status code and header
        else:
            if isinstance(resp[0], dict):

                content = dumps(resp[0])
                status_code = resp[1]
                content_type = {"Content-Type": "application/json"}
                resp = make_response((content, status_code, content_type))

            elif resp[0] is None:
                status_code = 200
                if len(resp) > 1:
                    if resp[1] is not None:
                        status_code = resp[1]
                resp = make_response(("", status_code, {"Content-Type": "text/html"}))

            else:
                content = str(resp[0])
                status_code = resp[1]

                if len(resp) <= 2:
                    content_type = {"Content-Type": "text/html"}
                else:
                    content_type = resp[2]
                resp = make_response((content, status_code, content_type))
            resp_msg = format_response(resp)

        debug_log.info(resp_msg)
        return resp
    return loggedfunc



class JWS_tool(base_token_tool):
    def __init__(self):
        self.slr = {}

    def get_SLR_payload(self):
        debug_log.info(dumps(self.slr, indent=2))
        base64_payload = self.slr["data"]["service_link_record"]["attributes"]["payload"]
        payload = self.decode_payload(base64_payload)
        return payload

    def get_CR_payload(self):
        base64_payload = self.slr["data"]["consent_record"]["attributes"]["payload"]
        payload = self.decode_payload(base64_payload)
        return payload

    def get_token_key(self):
        return self.get_SLR_payload()["token_key"]

    def get_operator_key(self):
        return self.get_SLR_payload()["operator_key"]

    def get_cr_keys(self):
        return self.get_SLR_payload()["cr_keys"]

    def get_rs_id(self):
        return self.get_CR_payload()["common_part"]["rs_id"]

    def get_source_cr_id(self):
        return self.get_CR_payload()["common_part"]["cr_id"]

    def get_surrogate_id(self):
        return self.get_CR_payload()["common_part"]["surrogate_id"]

    def get_sink_key(self):
        return self.get_SLR_payload()["token_key"]["key"]

    def get_dataset(self):
        return self.get_CR_payload()["common_part"]["rs_description"]["resource_set"]["dataset"]

    def get_source_service_id(self):
        return self.get_CR_payload()["common_part"]["subject_id"]


class Sequences:
    def __init__(self, name):
        """

        :param name:
        """
        self.logger = logging.getLogger("sequence")
        self.name = name

    def send_to(self, to, msg=""):
        return self.seq_tool(msg, to, )

    def reply_to(self, to, msg=""):
        return self.seq_tool(msg, to, dotted=True)

    def task(self, content):

        return self.seq_tool(msg=content, box=False, to=self.name)

    def seq_tool(self, msg=None, to="Change_Me", box=False, dotted=False):

        if box:
            form = 'Note over {}: {}'.format(self.name, msg)
            return self.seq_form(form, )
        elif dotted:
            form = "{}-->{}: {}".format(self.name, to, msg)
            return self.seq_form(form)
        else:
            form = "{}->{}: {}".format(self.name, to, msg)
            return self.seq_form(form)

    def seq_form(self, line):
        self.logger.info(dumps({"seq": line, "time": time.time()}))
        return {"seq": {}}
