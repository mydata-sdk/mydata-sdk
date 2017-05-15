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
            "sign_consent":     "api/account/consent/sign/",
            "consent":          "api/account/{account_id}/servicelink/{source_slr_id}/{sink_slr_id}/consent/",
            "auth_token":       "api/consent/{sink_cr_id}/authorizationtoken/",
            "last_csr":         "api/consent/{cr_id}/status/last/",
            "new_csr":          "api/consent/{cr_id}/status/"}  # Works as path to GET missing csr and POST new ones



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




    def get_AuthTokenInfo(self, cr_id):
        req = get(self.url + self.endpoint["auth_token"]
                  .replace("{sink_cr_id}", cr_id),
                  headers={'Api-Key-SDK': self.token}, timeout=self.timeout)
        if req.ok:
            templ = loads(req.text)
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Getting AuthToken info from account management failed.",
                                                "content": req.content},
                                        title=req.reason)
        return templ

    def getSUR_ID(self, service_id, account_id):
        debug_log.debug(
            "" + self.url + self.endpoint["surrogate"].replace("{account_id}", account_id).replace("{service_id}",
                                                                                                   service_id))

        req = get(self.url + self.endpoint["surrogate"].replace("{account_id}", account_id).replace("{service_id}",
                                                                                                    service_id),
                  headers={'Api-Key-SDK': self.token},
                  timeout=self.timeout)
        if req.ok:
            templ = loads(req.text)
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Getting surrogate_id from account management failed.",
                                                "content": req.content},
                                        title=req.reason)
        return templ

    def get_last_csr(self, cr_id):
        endpoint_url = self.url + self.endpoint["last_csr"].replace("{cr_id}", cr_id)
        debug_log.debug("" + endpoint_url)

        req = get(endpoint_url,
                  headers={'Api-Key-SDK': self.token},
                  timeout=self.timeout)
        if req.ok:
            templ = loads(req.text)
            payload = base_token_tool.decode_payload(templ["data"]["attributes"]["csr"]["payload"])
            debug_log.info("Got CSR payload from account:\n{}".format(dumps(payload, indent=2)))
            csr_id = payload["record_id"]
            return {"csr_id": csr_id}
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Getting last csr from account management failed.",
                                                "content": req.content},
                                        title=req.reason)

    def create_new_csr(self, cr_id, payload):
        endpoint_url = self.url + self.endpoint["new_csr"].replace("{cr_id}", cr_id)
        debug_log.debug("" + endpoint_url)
        payload = {"data": {"attributes": payload, "type": "ConsentStatusRecord"}}
        req = post(endpoint_url, json=payload,
                   headers={'Api-Key-SDK': self.token},
                   timeout=self.timeout)
        if req.ok:
            templ = loads(req.text)
            #tool = SLR_tool()
            #payload = tool.decode_payload(templ["data"]["attributes"]["csr"]["payload"])
            debug_log.info("Created CSR:\n{}".format(dumps(templ, indent=2)))
            #csr_id = payload["record_id"]

            return {"csr": templ}
        else:
            raise DetailedHTTPException(status=req.status_code,
                                        detail={"msg": "Creating new csr at account management failed.",
                                                "content": req.content},
                                        title=req.reason)

    def get_missing_csr(self, cr_id, csr_id):
        endpoint_url = self.url + self.endpoint["new_csr"].replace("{cr_id}", cr_id)
        debug_log.debug("" + endpoint_url)
        payload = {"csr_id": csr_id}
        req = get(endpoint_url, params=payload,
                   headers={'Api-Key-SDK': self.token},
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
                    "consentRecordPayload": {
                        "type": "ConsentRecord",
                        "attributes": source_cr["cr"]
                    },
                    "consentStatusRecordPayload": {
                        "type": "ConsentStatusRecord",
                        "attributes": source_csr,
                    }
                },
                "sink": {
                    "consentRecordPayload": {
                        "type": "ConsentRecord",
                        "attributes": sink_cr["cr"],
                    },
                    "consentStatusRecordPayload": {
                        "type": "ConsentStatusRecord",
                        "attributes": sink_csr,
                    },
                },
            },
        }

        slr_id_sink = template["data"]["sink"]["consentRecordPayload"]["attributes"]["common_part"]["slr_id"]
        slr_id_source = template["data"]["source"]["consentRecordPayload"]["attributes"]["common_part"]["slr_id"]
        # print(type(slr_id_source), type(slr_id_sink), account_id)
        debug_log.debug(dumps(template, indent=2))
        req = post(self.url + self.endpoint["consent"].replace("{account_id}", account_id)
                   .replace("{source_slr_id}", slr_id_source).
                   replace("{sink_slr_id}", slr_id_sink),
                   json=template,
                   headers={'Api-Key-SDK': self.token},
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

    # TODO: This should return list, now returns single object.
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

    def get_service_key(self, surrogate_id, kid):
        """

        """
        storage_row = self.query_db_multiple("select * from service_keys_tbl where surrogate_id = %s and kid = %s;",
                                             (surrogate_id, kid,), one=True)
        # Third item in this tuple should be the key JSON {token_key: {}, pop_key:{}}
        key_json_from_db = loads(storage_row[2])

        return key_json_from_db

    def store_service_key_json(self, kid, surrogate_id, key_json):
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        cursor.execute("INSERT INTO service_keys_tbl (kid, surrogate_id, key_json) \
            VALUES (%s, %s, %s);", (kid, surrogate_id, dumps(key_json)))

        db.commit()
#            cursor.execute("UPDATE service_keys_tbl SET key_json=%s WHERE kid=%s ;", (dumps(key_json), kid))
#            db.commit()
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
                # db.close()
            except IntegrityError as e:
                debug_log.info("")
                raise e
                cursor.execute("UPDATE session_store SET json=%s WHERE code=%s ;", (dumps(DictionaryToStore[key]), key))
                db.commit()
                # db.close()
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
            "version": "1.2",
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

    def gen_csr(self, account_id, consent_record_id, consent_status, previous_record_id):
        _tmpl = {
            "record_id": str(guid()),
            "surrogate_id": account_id,
            "cr_id": consent_record_id,
            "consent_status": consent_status,  # "Active/Disabled/Withdrawn"
            "iat": int(time.time()),
            "prev_record_id": previous_record_id,
        }
        return _tmpl

    def gen_auth_token(self, auth_token_info):
        operator_key = jwk.JWK(**self.get_key()["key"])
        slr_tool = SLR_tool()
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

class base_token_tool:

    @staticmethod
    def decode_payload(payload):
        payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
        content = decode(payload.encode())
        payload = loads(content.decode("utf-8"))
        debug_log.info("Decoded payload is:")
        debug_log.info(payload)
        return payload


class SLR_tool(base_token_tool):
    def __init__(self):
        self.slr = {
            "data": {
                "source": {
                    "consentRecord": {
                        "attributes": {
                            "cr": {
                                "payload": "IntcImNvbW1vbl9wYXJ0XCI6IHtcInNscl9pZFwiOiBcIjcwZjQwNTM1LTY2NzgtNDY1My1hZTdlLWJmMmU1MTc3NGFlNVwiLCBcInZlcnNpb25fbnVtYmVyXCI6IFwiU3RyaW5nXCIsIFwicnNfaWRcIjogXCIyXzM2MWNhOTY5LWMyNTktNDVkOS1iZWUwLTlmMzg4NmY2MjA1NlwiLCBcImNyX2lkXCI6IFwiMDQ3MmEyZTMtZGI2Yy00MTA5LWE1N2EtYzI1YWY5Y2IxNDUxXCIsIFwibm90X2FmdGVyXCI6IFwiU3RyaW5nXCIsIFwic3Vycm9nYXRlX2lkXCI6IFwiZTAyNTE3ZjgtNzkzZi00ZDNkLTg0MGEtNzJhNzFiN2E0OTViXzJcIiwgXCJub3RfYmVmb3JlXCI6IFwiU3RyaW5nXCIsIFwiaXNzdWVkXCI6IDE0NzE2MDQ0MDcsIFwiaXNzdWVkX2F0XCI6IFwiU3RyaW5nXCIsIFwic3ViamVjdF9pZFwiOiBcIjJcIn0sIFwicm9sZV9zcGVjaWZpY19wYXJ0XCI6IHtcImF1dGhfdG9rZW5faXNzdWVyX2tleVwiOiB7fSwgXCJyb2xlXCI6IFwiU291cmNlXCIsIFwicmVzb3VyY2Vfc2V0X2Rlc2NyaXB0aW9uXCI6IHtcInJlc291cmNlX3NldFwiOiB7XCJyc19pZFwiOiBcIlN0cmluZ1wiLCBcImRhdGFzZXRcIjogW3tcImRpc3RyaWJ1dGlvbl9pZFwiOiBcIlN0cmluZ1wiLCBcImRhdGFzZXRfaWRcIjogXCJTdHJpbmdcIn1dfX19LCBcImV4dGVuc2lvbnNcIjoge30sIFwibXZjclwiOiB7fX0i",
                                "signature": "JuZ_7tNcxO7_P9SGbBptllfVHNuZ2pQQZ4FLJeQISKBgA8pCra3i9Z81VbcachhLwnSBvv1qVVEuFEm5lnHR_g",
                                "protected": "eyJhbGciOiAiRVMyNTYifQ",
                                "header": {
                                    "jwk": {
                                        "x": "GfJCOXimGb3ZW4IJJIlKUZeoj8GCW7YYJRZgHuYUsds",
                                        "crv": "P-256",
                                        "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae",
                                        "kty": "EC",
                                        "y": "XIpGIZ7bz7uaoj_9L05CQSOw6VykuD6bK4r_OMVQSao"
                                    },
                                    "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
                                }
                            }
                        },
                        "type": "ConsentRecord"
                    }
                },
                "sink": {
                    "serviceLinkRecord": {
                        "attributes": {
                            "slr": {
                                "signatures": [
                                    {
                                        "signature": "aQB65Kv07kL9Q62INPZXMsNJuvfsEa0OuAI9c83DBTFK8cn1qFhDNZ76vVl84B0wImt3RgsPITNJiW3OvIGdag",
                                        "protected": "eyJhbGciOiAiRVMyNTYifQ",
                                        "header": {
                                            "jwk": {
                                                "x": "GfJCOXimGb3ZW4IJJIlKUZeoj8GCW7YYJRZgHuYUsds",
                                                "crv": "P-256",
                                                "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae",
                                                "kty": "EC",
                                                "y": "XIpGIZ7bz7uaoj_9L05CQSOw6VykuD6bK4r_OMVQSao"
                                            },
                                            "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
                                        }
                                    },
                                    {
                                        "signature": "MOBfIeQ6G4Bg6-4Q9v-Ta6_6Otd7sfXBg3YqVimtT0aL-9apMHl-i2lsuOKRySpe-tXnjQKoawjHpP8rTprqcG677TF0AbhS91LLepUsxt-NwdxnkhjDI8TSew0uVBirjY8-ZHYpLinu0ZMtAGoV-0WLuBPC-RBVqgOUQusJQSAfNyb5lpq2bTo7Xkry41XlrjdbE6tXMuGHmc2Hy9eytNf13597Q0xC0cOOlw92A92WT-6J9PLg4oArLgpBe8Tgc2GZp392DyyKvmTVENxEL1WgS5TlsxdKTH8tCSXwq5pWwkmm3Rnxfk3GUgV8hVaz0r3n1xX7EQKboondOpPeosOnpMu4ZrvoDB5aZz0KGTWuVqE7tHmVsG4lLQlww_e2KpTXfmxzLcpsOm_IfsyE-obI4_Dqi60ArjQ-kcMF6Djb0S-i1-PI-vEbSavYbcKdSjWVB1Z5-pw1rfch3inB2t5uzgjXVdipLH_jLvEUx0RrmRtG7Lq_cyJiV4wRW_YVgZbjVFZqwdsygo9-hg7YO9v-GgZr7d3z7nD6M1z4vJbJfmjXjt--2UtoY71DskxFDHUzajaMuwKiM1uBXt_TIUo3gEIM6xTpB5OEDHqN67aRTmhxK-Hqn1iHAxbnilcNjXIULiEfPQuAIpQWelO6j5drRzmyt04yIgrWQqQ5oFA",
                                        "protected": "eyJhbGciOiAiUlMyNTYifQ",
                                        "header": {
                                            "jwk": {
                                                "n": "v6QswzNJbJj2b9mE3IvPYDZx8K6MiJBDI9RJ1SwEWw0NsblAlxew3YdxvpE0iIfA-G5MHm5sG7DOmNCC9baILosVnG8UGI2QMfhZ8R4Vg-WlKQmGs_jNYaUnD2lr_gs6DTrzmfsYj_UH4NHCCm9CTW-f1s4vMpFaYAPWfTCK2OogBX0BH3f_Q8lFXmdllLN0lT5p18QY9xa9hqWkIbAOPH3Tv66kfJHdSbKeT7HqOeKRj4aBH_kokJWZcMmQAHYPuR2Y46nDQdYKRt822tmEONalupSzNdEErlSzKZ5uPileqIAitHTG0QFzL1ZfiqfI861nrKlFi3LOhXGzk_skXZYZGvLLAZ1TtBIUcM97VyBlJVNRpK9fypLyHN3ezxuazwwZ4gi8-T39E2Xpr0TRj5eVfoflau6LF4MgwQTs6PyKzkwKlcipTcrmMMhoT9MYNih_Sb2E7qlF_gXEfgFzcXO8AkArwGoNlpvYdZdNyu4u6mviH7-ZK6YnkudI6qRCrbG7sYltGXO809NdSnGklMqXDSvghlgHvagLyXJ4C8geRH_9aGzYVjweYmwQxgBMFtpvzotd1KIoeFkKFIXf1p9P02AwgQJSVTdVHltNU9Vkom-TLcO3SZ5FvpC5W1hS67bkD_qStQPWAZ-RtWH0QkjJFGdQVLdK07uZNkSVee8",
                                                "kid": "SRVMGNT-RSA-4096",
                                                "e": "AQAB",
                                                "kty": "RSA"
                                            },
                                            "kid": "SRVMGNT-RSA-4096"
                                        }
                                    }
                                ],
                                "payload": "IntcIm9wZXJhdG9yX2lkXCI6IFwiQUNDLUlELVJBTkRPTVwiLCBcImNyZWF0ZWRcIjogMTQ3MTYwNDQwNSwgXCJzdXJyb2dhdGVfaWRcIjogXCJkMTJjN2UyOC04NzRiLTQwNDAtYmVjNS02NzkzYTYwMzhjMTlfMlwiLCBcInRva2VuX2tleVwiOiB7XCJrZXlcIjoge1wiblwiOiBcInY2UXN3ek5KYkpqMmI5bUUzSXZQWURaeDhLNk1pSkJESTlSSjFTd0VXdzBOc2JsQWx4ZXczWWR4dnBFMGlJZkEtRzVNSG01c0c3RE9tTkNDOWJhSUxvc1ZuRzhVR0kyUU1maFo4UjRWZy1XbEtRbUdzX2pOWWFVbkQybHJfZ3M2RFRyem1mc1lqX1VINE5IQ0NtOUNUVy1mMXM0dk1wRmFZQVBXZlRDSzJPb2dCWDBCSDNmX1E4bEZYbWRsbExOMGxUNXAxOFFZOXhhOWhxV2tJYkFPUEgzVHY2NmtmSkhkU2JLZVQ3SHFPZUtSajRhQkhfa29rSldaY01tUUFIWVB1UjJZNDZuRFFkWUtSdDgyMnRtRU9OYWx1cFN6TmRFRXJsU3pLWjV1UGlsZXFJQWl0SFRHMFFGekwxWmZpcWZJODYxbnJLbEZpM0xPaFhHemtfc2tYWllaR3ZMTEFaMVR0QklVY005N1Z5QmxKVk5ScEs5ZnlwTHlITjNlenh1YXp3d1o0Z2k4LVQzOUUyWHByMFRSajVlVmZvZmxhdTZMRjRNZ3dRVHM2UHlLemt3S2xjaXBUY3JtTU1ob1Q5TVlOaWhfU2IyRTdxbEZfZ1hFZmdGemNYTzhBa0Fyd0dvTmxwdllkWmROeXU0dTZtdmlINy1aSzZZbmt1ZEk2cVJDcmJHN3NZbHRHWE84MDlOZFNuR2tsTXFYRFN2Z2hsZ0h2YWdMeVhKNEM4Z2VSSF85YUd6WVZqd2VZbXdReGdCTUZ0cHZ6b3RkMUtJb2VGa0tGSVhmMXA5UDAyQXdnUUpTVlRkVkhsdE5VOVZrb20tVExjTzNTWjVGdnBDNVcxaFM2N2JrRF9xU3RRUFdBWi1SdFdIMFFrakpGR2RRVkxkSzA3dVpOa1NWZWU4XCIsIFwiZVwiOiBcIkFRQUJcIiwgXCJrdHlcIjogXCJSU0FcIiwgXCJraWRcIjogXCJTUlZNR05ULVJTQS00MDk2XCJ9fSwgXCJsaW5rX2lkXCI6IFwiYTk4ZDg4Y2ItZDA3ZS00YTMyLTk3ODctY2IzODgxZDBiMDZlXCIsIFwib3BlcmF0b3Jfa2V5XCI6IHtcInVzZVwiOiBcInNpZ1wiLCBcImVcIjogXCJBUUFCXCIsIFwia3R5XCI6IFwiUlNBXCIsIFwiblwiOiBcIndITUFwQ2FVSkZpcHlGU2NUNzgxd2VuTm5mbU5jVkQxZTBmSFhfcmVfcWFTNWZvQkJzN1c0aWE1bnVxNjVFQWJKdWFxaGVPR2FEamVIaVU4V1Q5cWdnYks5cTY4SXZUTDN1bjN6R2o5WmQ3N3MySXdzNE1BSW1EeWN3Rml0aDE2M3lxdW9ETXFMX1YySXl5Mm45Uzloa1M5ZkV6cXJsZ01sYklnczJtVkJpNmdWVTJwYnJTN0gxUGFSV194YlFSX1puN19laV9uOFdlWFA1d2NEX3NJYldNa1NCc3VVZ21jam9XM1ktNW1ERDJWYmRFejJFbWtZaTlHZmstcDlBenlVbk56ZkIyTE1jSk1aekpWUWNYaUdCTzdrcG9uRkEwY3VIMV9CR0NsZXJ6Mnh2TWxXdjlPVnZzN3ZDTmRlQV9mano2eloyMUtadVo0RG1nZzBrOTRsd1wifSwgXCJ2ZXJzaW9uXCI6IFwiMS4yXCIsIFwiY3Jfa2V5c1wiOiBbe1wieVwiOiBcIlhJcEdJWjdiejd1YW9qXzlMMDVDUVNPdzZWeWt1RDZiSzRyX09NVlFTYW9cIiwgXCJ4XCI6IFwiR2ZKQ09YaW1HYjNaVzRJSkpJbEtVWmVvajhHQ1c3WVlKUlpnSHVZVXNkc1wiLCBcImNydlwiOiBcIlAtMjU2XCIsIFwia3R5XCI6IFwiRUNcIiwgXCJraWRcIjogXCJhY2Mta2lkLTM4MDJmZDE3LTQ5ZjQtNDhmYy04YWMxLTA5NjI0YTUyYTNhZVwifV0sIFwic2VydmljZV9pZFwiOiBcIjFcIn0i"
                            }
                        },
                        "type": "ServiceLinkRecord"
                    }
                }
            }
        }

    def get_SLR_payload(self):
        debug_log.info(dumps(self.slr, indent=2))
        base64_payload = self.slr["data"]["sink"]["serviceLinkRecord"]["attributes"]["slr"]["attributes"]["slr"][
            "payload"]  # TODO: This is a workaround for structure repetition.
        payload = self.decode_payload(base64_payload)
        return payload

    def get_CR_payload(self):
        base64_payload = self.slr["data"]["source"]["consentRecord"]["attributes"]["cr"]["attributes"]["cr"][
            "payload"]  # TODO: This is a workaround for structure repetition.
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

    def get_sink_service_id(self):
        return self.slr["data"]["sink"]["serviceLinkRecord"]["attributes"]["slr"]["attributes"]["service_id"]


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