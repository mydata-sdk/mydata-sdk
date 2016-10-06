# -*- coding: utf-8 -*-
import importlib
import logging
import pkgutil
from json import dumps, load, dump
import time
from datetime import datetime
from flask import Blueprint
from flask_restful import Api
import jsonschema
import db_handler
from sqlite3 import IntegrityError
from DetailedHTTPException import  DetailedHTTPException

debug_log = logging.getLogger("debug")


def validate_json(schema, json):  # "json" here needs to be python dict.
    errors = []
    validator = jsonschema.Draft4Validator(schema)
    validator.check_schema(schema)
    for error in sorted(validator.iter_errors(json), key=str):
        debug_log.warning("Validation error found: {}".format(repr(error)))
        errors.append(repr(error))
    return errors


class Helpers:
    def __init__(self, app_config):
        self.host = app_config["MYSQL_HOST"]
        self.cert_key_path = app_config["CERT_KEY_PATH"]
        self.keysize = app_config["KEYSIZE"]
        self.user = app_config["MYSQL_USER"]
        self.passwd = app_config["MYSQL_PASSWORD"]
        self.db = app_config["MYSQL_DB"]
        self.port = app_config["MYSQL_PORT"]
        self.service_id = app_config["SERVICE_ID"]

    def get_key(self):
        keysize = self.keysize
        cert_key_path = self.cert_key_path
        gen3 = {"generate": "RSA", "size": keysize, "kid": self.service_id}
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
        full_key = loads(service_key)
        protti = {"alg": "RS256"}
        headeri = {"kid": self.service_id, "jwk": public_key}
        return {"pub:": public_key,
                "key": full_key,
                "prot": protti,
                "header": headeri}

    def query_db(self, query, args=()):
        '''
        Simple queries to DB
        :param query: SQL query
        :param args: Arguments to inject into the query
        :return: Single hit for the given query
        '''
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        cur = cursor.execute(query, args)
        try:
            rv = cursor.fetchone()  # Returns tuple
            debug_log.info(rv)
            if rv is not None:
                db.close()
                return rv[1]  # The second value in the tuple.
            else:
                return None
        except Exception as e:
            debug_log.exception(e)
            debug_log.info(cur)
            db.close()
            return None


    def storeJSON(self, DictionaryToStore):
        """
        Store SLR into database
        :param DictionaryToStore: Dictionary in form {"key" : "dict_to_store"}
        :return: 
        """
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)
        for key in DictionaryToStore:
            debug_log.info(key)
            try:
                cursor.execute("INSERT INTO storage (surrogate_id,json) \
                    VALUES (%s, %s)", (key, dumps(DictionaryToStore[key])))
                db.commit()
            except IntegrityError as e:
                cursor.execute("UPDATE storage SET json=%s WHERE surrogate_id=%s ;", (dumps(DictionaryToStore[key]), key))
                db.commit()
        db.close()

    def storeToken(self, DictionaryToStore):
        """
        Store token into database
        :param DictionaryToStore: Dictionary in form {"key" : "dict_to_store"}
        :return: 
        """
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)
        for key in DictionaryToStore:
            debug_log.info(key)
            try:
                cursor.execute("INSERT INTO token_storage (cr_id,token) \
                    VALUES (%s, %s)", (key, dumps(DictionaryToStore[key])))
                db.commit()
            except IntegrityError as e:  # Rewrite incase we get new token.
                cursor.execute("UPDATE token_storage SET token=%s WHERE cr_id=%s ;", (dumps(DictionaryToStore[key]), key))
                db.commit()
        db.close()

    def storeCode(self, code):
        """
        Store generated code into database
        :param code: 
        :return: None
        """
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        code_key = list(code.keys())[0]
        code_value = code[code_key]
        cursor.execute("INSERT INTO codes (ID,code) \
            VALUES (%s, %s)", (code_key, code_value))
        db.commit()
        debug_log.info("{}  {}".format(code_key, code_value))
        db.close()

    def add_surrogate_id_to_code(self, code, surrogate_id):
        """
        Link code with a surrogate_id
        :param code: 
        :param surrogate_id: 
        :return: None
        """
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info("Code we look up is {}".format(code))
        code = self.query_db("select * from codes where ID = %s;", (code,))
        debug_log.info("Result for query: {}".format(code))
        code_from_db = code
        code_is_valid_and_unused = "!" in code_from_db
        if (code_is_valid_and_unused):
            cursor.execute("UPDATE codes SET code=%s WHERE ID=%s ;", (surrogate_id, code))
            db.commit()
            db.close()
        else:
            raise Exception("Invalid code")


    def validate_cr(self, cr_id, surrogate_id):
        """
        Lookup and validate ConsentRecord based on given CR_ID
        :param cr_id:
        :return: CR if found and validated.
        """
        # TODO: query_db is not really optimal when making two separate queries in row.
        cr = self.query_db("select * from cr_storage where cr_id = %s;", (cr_id,))
        csr = self.query_db("select * from csr_storage where cr_id = %s;", (cr_id,))
        cr_from_db = loads(cr)
        csr_from_db = loads(csr)

        # We need to get cr and csr to properly use CR tool
        debug_log.info("Printing CR from DB:")
        debug_log.info(cr)
        debug_log.info("Printing CSR from DB:")
        debug_log.info(csr)
        combined = {"cr": cr_from_db, "csr": csr_from_db}
        debug_log.info(dumps(combined, indent=2))
        # Using CR tool we get nice helper functions.
        tool = CR_tool()
        tool.cr = combined
        # To fetch key from SLR we need surrogate_id.
        # We get this as parameter so as further check we verify its same as in cr.
        surrogate_id_from_cr = tool.get_surrogate_id()
        debug_log.info("Surrogate_id as parameter was ({}) and from CR ({})".format(surrogate_id, surrogate_id_from_cr))
        if surrogate_id_from_cr != surrogate_id:
            raise NameError("User surrogate_id doesn't match surrogate_id in consent record.")
        # Now we fetch the SLR and put it to SLR_Tool
        slr_tool = SLR_tool()
        slr = self.get_slr(surrogate_id)
        slr_tool.slr = slr
        # Fetch key from SLR.
        keys = slr_tool.get_cr_keys()

        # Verify the CR with the keys from SLR
        # Check integrity (signature)

        tool.verify_cr(keys)
        tool.verify_csr(keys)
        debug_log.info("Verified cr/csr ({}) for surrogate_id ({}) ".format(cr_id, surrogate_id))

        combined_decrypted = dumps({"cr": tool.get_CR_payload(), "csr": tool.get_CSR_payload()}, indent=2)
        debug_log.info(combined_decrypted)
        # Check that state is "Active"
        state = tool.get_state()
        if state != "Active":
            raise ValueError("CR state is not 'Active' but ({})".format(state))

        # Check "Issued" timestamp
        time_now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S %Z")
        issued_in_cr = tool.get_issued()
        issued = datetime.strptime(issued_in_cr, "%Y-%m-%dT%H:%M:%S %Z")
        if time_now<issued:
            raise EnvironmentError("This CR is issued in the future!")
        debug_log.info("Issued timestamp is valid.")

        # Check "Not Before" timestamp
        not_before_in_cr = tool.get_not_before()
        not_before = datetime.strptime(not_before_in_cr, "%Y-%m-%dT%H:%M:%S %Z")
        if time_now<not_before:
            raise EnvironmentError("This CR will be available in the future, not yet.")
        debug_log.info("Not Before timestamp is valid.")

        # Check "Not After" timestamp
        not_after_in_cr = tool.get_not_after()
        not_after = datetime.strptime(not_after_in_cr, "%Y-%m-%dT%H:%M:%S %Z")
        if time_now>not_after:
            raise EnvironmentError("This CR is expired.")
        debug_log.info("Not After timestamp is valid.")
        # CR validated.


        return combined


    def verifyCode(self, code):
        """
        Verify that code is found in database
        :param code: 
        :return: Boolean True if code is found in db. 
        """
        code = self.query_db("select * from codes where ID = %s;", (code,))
        if code is not None:
            return True
        return False

    def verifySurrogate(self, code, surrogate):
        """
        Verify that surrogate id matches code in database
        :param code: 
        :param surrogate: surrogate_id
        :return: Boolean True if surrogate_id matches code
        """
        code = self.query_db("select * from codes where ID = %s AND code = %s;", (code, surrogate))
        if code is not None:
            # TODO: Could we remove code and surrogate_id after this check to ensure they wont be abused later.
            return True
        return False

    def get_slr(self, surrogate_id):
        """
        Fetch SLR for given surrogate_id from the database
        :param surrogate_id: surrogate_id
        :return: Return SLR made for given surrogate_id or None
        """
        storage_row = self.query_db("select * from storage where surrogate_id = %s;", (surrogate_id,))
        slr_from_db = loads(storage_row)
        return slr_from_db

    def storeCR_JSON(self, DictionaryToStore):
        """
        Store CR into database
        :param DictionaryToStore: Dictionary in form {"key" : "dict_to_store"}
        :return: None
        """
        cr_id = DictionaryToStore["cr_id"]
        rs_id = DictionaryToStore["rs_id"]
        surrogate_id = DictionaryToStore["surrogate_id"]
        slr_id = DictionaryToStore["slr_id"]
        json = DictionaryToStore["json"]
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)
        # debug_log.info(key)
        try:
            cursor.execute("INSERT INTO cr_storage (cr_id, surrogate_id, slr_id, rs_id, json) \
                VALUES (%s, %s, %s, %s, %s)", (cr_id, surrogate_id, slr_id, rs_id, dumps(json)))
            db.commit()
        except IntegrityError as e:
            # db.execute("UPDATE cr_storage SET json=? WHERE cr_id=? ;", [dumps(DictionaryToStore[key]), key])
            # db.commit()
            db.rollback()
            raise DetailedHTTPException(detail={"msg": "Adding CR to the database has failed.",},
                                        title="Failure in CR storage", exception=e)

    def storeCSR_JSON(self, DictionaryToStore):
        """
        Store CSR into database
        :param DictionaryToStore: Dictionary in form {"key" : "dict_to_store"}
        :return: None
        """
        cr_id = DictionaryToStore["cr_id"]
        rs_id = DictionaryToStore["rs_id"]
        surrogate_id = DictionaryToStore["surrogate_id"]
        slr_id = DictionaryToStore["slr_id"]
        json = DictionaryToStore["json"]
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)
        # debug_log.info(key)
        try:
            cursor.execute("INSERT INTO csr_storage (cr_id, surrogate_id, slr_id, rs_id, json) \
                VALUES (%s, %s, %s, %s, %s)", [cr_id, surrogate_id, slr_id, rs_id, dumps(json)])
            db.commit()
        except IntegrityError as e:
            # db.execute("UPDATE csr_storage SET json=? WHERE cr_id=? ;", [dumps(DictionaryToStore[key]), key])
            # db.commit()
            db.rollback()
            raise DetailedHTTPException(detail={"msg": "Adding CSR to the database has failed.",},
                                        title="Failure in CSR storage", exception=e)


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

from base64 import urlsafe_b64decode as decode
from json import loads
class SLR_tool:
    def __init__(self):
        self.slr = {
                  "code": "7e4f7cf6-f169-4430-9b23-a4820446fe71",
                  "data": {
                    "slr": {
                      "type": "ServiceLinkRecord",
                      "attributes": {
                        "slr": {
                          "payload": "IntcIm9wZXJhdG9yX2lkXCI6IFwiQUNDLUlELVJBTkRPTVwiLCBcImNyZWF0ZWRcIjogMTQ3MTM0NDYyNiwgXCJzdXJyb2dhdGVfaWRcIjogXCI5YjQxNmE5Zi1jYjRmLTRkNWMtYjJiZS01OWQxYjc3ZjJlZmFfMVwiLCBcInRva2VuX2tleVwiOiB7XCJrZXlcIjoge1wieVwiOiBcIkN0NGNHMnpPQzdrano5VWF1WHFqcTRtZ0d0bEdXcDJjcWZneVVlaUU4U2dcIiwgXCJ4XCI6IFwiUnJueHZoZjVsZXppQTZyZms4ZDlRbV96bXd2SDc5X2U5eUhBS2ZJR2dFRVwiLCBcImNydlwiOiBcIlAtMjU2XCIsIFwia3R5XCI6IFwiRUNcIiwgXCJraWRcIjogXCJTUlZNR05ULUlESzNZXCJ9fSwgXCJsaW5rX2lkXCI6IFwiNDJhMzVhN2QtMjkxZS00N2UzLWIyMmYtOTk2NjJmNjgzNDEzXCIsIFwib3BlcmF0b3Jfa2V5XCI6IHtcInVzZVwiOiBcInNpZ1wiLCBcImVcIjogXCJBUUFCXCIsIFwia3R5XCI6IFwiUlNBXCIsIFwiblwiOiBcIndITUFwQ2FVSkZpcHlGU2NUNzgxd2VuTm5mbU5jVkQxZTBmSFhfcmVfcWFTNWZvQkJzN1c0aWE1bnVxNjVFQWJKdWFxaGVPR2FEamVIaVU4V1Q5cWdnYks5cTY4SXZUTDN1bjN6R2o5WmQ3N3MySXdzNE1BSW1EeWN3Rml0aDE2M3lxdW9ETXFMX1YySXl5Mm45Uzloa1M5ZkV6cXJsZ01sYklnczJtVkJpNmdWVTJwYnJTN0gxUGFSV194YlFSX1puN19laV9uOFdlWFA1d2NEX3NJYldNa1NCc3VVZ21jam9XM1ktNW1ERDJWYmRFejJFbWtZaTlHZmstcDlBenlVbk56ZkIyTE1jSk1aekpWUWNYaUdCTzdrcG9uRkEwY3VIMV9CR0NsZXJ6Mnh2TWxXdjlPVnZzN3ZDTmRlQV9mano2eloyMUtadVo0RG1nZzBrOTRsd1wifSwgXCJ2ZXJzaW9uXCI6IFwiMS4yXCIsIFwiY3Jfa2V5c1wiOiBbe1wieVwiOiBcIlhaeWlveV9BME5qQ3Q1ZGt6OW5MOGI3YXdQRl9Cck5iYzVObjFOTTdXS0FcIiwgXCJ4XCI6IFwiR3ZaVEdpMllSb0VCblc2QzB4clpRQ0tNeWwza2lNcjgtRVoySU1ocnpXb1wiLCBcImNydlwiOiBcIlAtMjU2XCIsIFwia3R5XCI6IFwiRUNcIiwgXCJraWRcIjogXCJhY2Mta2lkLTg1MTVhYjQ2LTlkODItNDUzNC1hZDFmLTYzZDFlNDdiZDY2YlwifV0sIFwic2VydmljZV9pZFwiOiBcIjFcIn0i",
                          "signatures": [
                            {
                              "header": {
                                "jwk": {
                                  "x": "GvZTGi2YRoEBnW6C0xrZQCKMyl3kiMr8-EZ2IMhrzWo",
                                  "kty": "EC",
                                  "crv": "P-256",
                                  "y": "XZyioy_A0NjCt5dkz9nL8b7awPF_BrNbc5Nn1NM7WKA",
                                  "kid": "acc-kid-8515ab46-9d82-4534-ad1f-63d1e47bd66b"
                                },
                                "kid": "acc-kid-8515ab46-9d82-4534-ad1f-63d1e47bd66b"
                              },
                              "protected": "eyJhbGciOiAiRVMyNTYifQ",
                              "signature": "fsSuhqLp6suUuT8waseMlpYcFx4vqIviIteBLUNWPUOubHPDY64sbpfx_flpPFymxG_t8r3Ptb96kv-ZDyjb7g"
                            },
                            {
                              "header": {
                                "jwk": {
                                  "x": "Rrnxvhf5leziA6rfk8d9Qm_zmwvH79_e9yHAKfIGgEE",
                                  "kty": "EC",
                                  "crv": "P-256",
                                  "y": "Ct4cG2zOC7kjz9UauXqjq4mgGtlGWp2cqfgyUeiE8Sg",
                                  "kid": "SRVMGNT-IDK3Y"
                                },
                                "kid": "SRVMGNT-IDK3Y"
                              },
                              "protected": "eyJhbGciOiAiRVMyNTYifQ",
                              "signature": "3rZCfJxvpD7covQjH_lhkJwId8ynVIMLZ6t1obiCrlwJOJe_Yc7dmImi10w8tc9_7c7u35_ysiD72wIlbJ4oFQ"
                            }
                          ]
                        }
                      }
                    },
                    "meta": {
                      "slsr_id": "374707b7-a60b-4596-9f3a-6a5affa414c3",
                      "slr_id": "42a35a7d-291e-47e3-b22f-99662f683413"
                    },
                    "slsr": {
                      "type": "ServiceLinkStatusRecord",
                      "attributes": {
                        "slsr": {
                          "header": {
                            "jwk": {
                              "x": "GvZTGi2YRoEBnW6C0xrZQCKMyl3kiMr8-EZ2IMhrzWo",
                              "kty": "EC",
                              "crv": "P-256",
                              "y": "XZyioy_A0NjCt5dkz9nL8b7awPF_BrNbc5Nn1NM7WKA",
                              "kid": "acc-kid-8515ab46-9d82-4534-ad1f-63d1e47bd66b"
                            },
                            "kid": "acc-kid-8515ab46-9d82-4534-ad1f-63d1e47bd66b"
                          },
                          "protected": "eyJhbGciOiAiRVMyNTYifQ",
                          "payload": "IntcInNscl9pZFwiOiBcIjQyYTM1YTdkLTI5MWUtNDdlMy1iMjJmLTk5NjYyZjY4MzQxM1wiLCBcImFjY291bnRfaWRcIjogXCIxXCIsIFwic2xfc3RhdHVzXCI6IFwiQWN0aXZlXCIsIFwicmVjb3JkX2lkXCI6IFwiMzc0NzA3YjctYTYwYi00NTk2LTlmM2EtNmE1YWZmYTQxNGMzXCIsIFwiaWF0XCI6IDE0NzEzNDQ2MjYsIFwicHJldl9yZWNvcmRfaWRcIjogXCJOVUxMXCJ9Ig",
                          "signature": "cfj3Zm5ICVtTdUJigKGTxJX4V8vzs1e9qVj83hPmiD-XJonrBRW60zQN-3lRTuJithFbrGgBJShGj1InuNGMsw"
                        }
                      }
                    },
                    "surrogate_id": "9b416a9f-cb4f-4d5c-b2be-59d1b77f2efa_1"
                  }}
    def decrypt_payload(self, payload):
        payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
        content = decode(payload.encode())
        payload = loads(loads(content.decode("utf-8")))
        return payload

    def get_SLR_payload(self):
        base64_payload = self.slr["data"]["slr"]["attributes"]["slr"]["payload"]
        payload = self.decrypt_payload(base64_payload)
        return payload

    def get_SLSR_payload(self):
        base64_payload =  self.slr["data"]["slsr"]["attributes"]["slsr"]["payload"]
        payload = self.decrypt_payload(base64_payload)
        return payload

    def get_token_key(self):
        return self.get_SLR_payload()["token_key"]

    def get_operator_key(self):
        return self.get_SLR_payload()["operator_key"]

    def get_cr_keys(self):
        return self.get_SLR_payload()["cr_keys"]


#
# sl = SLR_tool()
# print(dumps(sl.get_CR_payload(), indent=2))
# print(sl.get_SLR_payload())
# print(sl.get_cr_keys())
# print(sl.get_rs_id())
# print(sl.get_rs_set())
# print(sl.get_slr_id())
# print(sl.get_sink_surrogate_id())
# print(sl.get_source_surrogate_id())

from jwcrypto import jwk, jws
class CR_tool:
    def __init__(self):
        self.cr = {
  "csr": {
    "signature": "e4tiFSvnqUb8k1U6BXC5WhbkQWVJZqMsDqc3efPRkBcL1cM21mSJXYOS4dSiCx4ak8S8S1IKN4wcyuAxXfrGeQ",
    "payload": "IntcImNvbW1vbl9wYXJ0XCI6IHtcInNscl9pZFwiOiBcImJhYmY5Mjc3LWEyZmItNGI4MS1iMTYyLTE4ZTI5MzUyNzYxN1wiLCBcInZlcnNpb25fbnVtYmVyXCI6IFwiU3RyaW5nXCIsIFwicnNfaWRcIjogXCIyXzYyNmE3YmZiLTk0MmEtNDI2ZC1hNDc2LWE0Mzk5NmYyMDAwNVwiLCBcImNyX2lkXCI6IFwiMjlmZmRkZmMtNjBhMS00YmYwLTkzMWMtNGQ1ZWYwMmQ2N2YyXCIsIFwiaXNzdWVkXCI6IDE0NzE1OTMwMjYsIFwic3ViamVjdF9pZFwiOiBcIjFcIiwgXCJub3RfYmVmb3JlXCI6IFwiU3RyaW5nXCIsIFwibm90X2FmdGVyXCI6IFwiU3RyaW5nXCIsIFwiaXNzdWVkX2F0XCI6IFwiU3RyaW5nXCIsIFwic3Vycm9nYXRlX2lkXCI6IFwiZTZlMjdlNzUtNjUxZi00Y2I0LTg5ZTItYTUxZWI5NDllYjYwXzJcIn0sIFwicm9sZV9zcGVjaWZpY19wYXJ0XCI6IHtcInJvbGVcIjogXCJTaW5rXCIsIFwidXNhZ2VfcnVsZXNcIjogW1wiQWxsIHlvdXIgY2F0cyBhcmUgYmVsb25nIHRvIHVzXCIsIFwiU29tZXRoaW5nIHJhbmRvbVwiXX0sIFwiZXh0ZW5zaW9uc1wiOiB7fSwgXCJtdmNyXCI6IHt9fSI",
    "protected": "eyJhbGciOiAiRVMyNTYifQ",
    "header": {
      "jwk": {
        "kty": "EC",
        "crv": "P-256",
        "y": "XIpGIZ7bz7uaoj_9L05CQSOw6VykuD6bK4r_OMVQSao",
        "x": "GfJCOXimGb3ZW4IJJIlKUZeoj8GCW7YYJRZgHuYUsds",
        "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
      },
      "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
    }
  },
  "cr": {
    "signature": "fiiVhAPxzYGgkV3D43FvgKSdIvDrsyMm_Vz4WWhBoLaXbTcZKNEvKL5Tx1O6YRwShOc9plK7YRxgWyY9OYd7zA",
    "payload": "IntcImFjY291bnRfaWRcIjogXCJlNmUyN2U3NS02NTFmLTRjYjQtODllMi1hNTFlYjk0OWViNjBfMlwiLCBcImNyX2lkXCI6IFwiMjlmZmRkZmMtNjBhMS00YmYwLTkzMWMtNGQ1ZWYwMmQ2N2YyXCIsIFwicHJldl9yZWNvcmRfaWRcIjogXCJudWxsXCIsIFwicmVjb3JkX2lkXCI6IFwiZTBiZDk1MTUtNjA5Zi00YzMxLThiMmQtZDliMTY5NjdiZmQzXCIsIFwiaWF0XCI6IDE0NzE1OTMwMjYsIFwiY29uc2VudF9zdGF0dXNcIjogXCJBY3RpdmVcIn0i",
    "protected": "eyJhbGciOiAiRVMyNTYifQ",
    "header": {
      "jwk": {
        "kty": "EC",
        "crv": "P-256",
        "y": "XIpGIZ7bz7uaoj_9L05CQSOw6VykuD6bK4r_OMVQSao",
        "x": "GfJCOXimGb3ZW4IJJIlKUZeoj8GCW7YYJRZgHuYUsds",
        "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
      },
      "kid": "acc-kid-3802fd17-49f4-48fc-8ac1-09624a52a3ae"
    }
  }
}
    def decrypt_payload(self, payload):
        #print("payload :\n", slr)
        #print("Before Fix:", payload)
        payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
        #print("After Fix :", payload)
        content = decode(payload.encode())
        payload = loads(loads(content.decode("utf-8")))
        return payload

    def get_CR_payload(self):
        base64_payload = self.cr["cr"]["payload"]
        payload = self.decrypt_payload(base64_payload)
        return payload

    def get_CSR_payload(self):
        base64_payload = self.cr["csr"]["payload"]
        payload = self.decrypt_payload(base64_payload)
        return payload

    def get_cr_id_from_csr(self):
        return self.get_CSR_payload()["cr_id"]

    def get_prev_record_id(self):
        return self.get_CSR_payload()["prev_record_id"]

    def get_cr_id_from_cr(self):
        return self.get_CR_payload()["common_part"]["cr_id"]

    def cr_id_matches_in_csr_and_cr(self):
        return self.get_cr_id_from_cr() == self.get_cr_id_from_csr()

    def get_usage_rules(self):
        return self.get_CR_payload()["role_specific_part"]["usage_rules"]

    def get_slr_id(self):
        return self.get_CR_payload()["common_part"]["slr_id"]

    def get_issued(self):
        return self.get_CR_payload()["common_part"]["issued"]

    def get_not_before(self):
        return self.get_CR_payload()["common_part"]["not_before"]

    def get_not_after(self):
        return self.get_CR_payload()["common_part"]["not_after"]

    def get_rs_id(self):
        return self.get_CR_payload()["common_part"]["rs_id"]

    def get_state(self):
        return self.get_CSR_payload()["consent_status"]

    def get_subject_id(self):
        return self.get_CR_payload()["common_part"]["subject_id"]

    def get_surrogate_id(self):
        return self.get_CR_payload()["common_part"]["surrogate_id"]

    def get_role(self):
        return self.get_CR_payload()["role_specific_part"]["role"]

    def verify_cr(self, keys):
        for key in keys:
            cr_jwk = jwk.JWK(**key)
            cr_jws = jws.JWS()
            cr_jws.deserialize(dumps(self.cr["cr"]))

            try:
                cr_jws.verify(cr_jwk)
                return True
            except Exception as e:
                pass
                #print(repr(e))
                #return False
        return False


    def verify_csr(self, keys):
        for key in keys:
            cr_jwk = jwk.JWK(**key)
            csr_jws = jws.JWS()
            csr_jws.deserialize(dumps(self.cr["csr"]))
            try:
                csr_jws.verify(cr_jwk)
                return True
            except Exception as e:
                pass
                #print(repr(e))
                #return False
        return False

#crt = CR_tool()
#print (dumps(crt.get_CR_payload(), indent=2))
#print (dumps(crt.get_CSR_payload(), indent=2))
#print(crt.get_role())
# print(crt.get_cr_id())
# print(crt.get_usage_rules())
# print(crt.get_surrogate_id())