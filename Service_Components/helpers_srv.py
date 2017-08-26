# -*- coding: utf-8 -*-
import importlib
import logging
import pkgutil
import time
import urllib
from json import load, dump
from sqlite3 import IntegrityError
import collections
import jsonschema
from flask import Blueprint
from flask_restful import Api
from requests import get

import db_handler
from DetailedHTTPException import DetailedHTTPException

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
        self.keytype = app_config["KEYTYPE"]
        self.user = app_config["MYSQL_USER"]
        self.passwd = app_config["MYSQL_PASSWORD"]
        self.db = app_config["MYSQL_DB"]
        self.port = app_config["MYSQL_PORT"]
        self.service_id = app_config["SERVICE_ID"]


    def get_key(self):
        cert_key_path = self.cert_key_path
        if self.keytype == "RSA":
            gen3 = {"generate": "RSA", "size": self.keysize, "kid": self.service_id}
            protti = {"alg": "RS256"}
        elif self.keytype == "EC256":
            gen3 = {"generate": "EC", "cvr": "P-256", "kid": self.service_id}
            protti = {"alg": "ES256"}
        else:  # Defaulting to EC256
            gen3 = {"generate": "EC", "cvr": "P-256", "kid": self.service_id}
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

        headeri = {"kid": self.service_id, "jwk": public_key}
        return {"pub": public_key,
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

        result = self.query_db_multiple(query, args=args, one=True)
        if result is not None:
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
                rv = cursor.fetchone()  # Returns tuple
                debug_log.info(rv)
                if rv is not None:
                    db.close()
                    return rv  # the tuple.
                else:
                    return None
            except Exception as e:
                debug_log.exception(e)
                debug_log.info(cur)
                db.close()
                return None
        else:
            try:
                rv = cursor.fetchall()  # Returns tuple
                debug_log.info(rv)
                if rv is not None:
                    db.close()
                    return rv  # This should be list of tuples [(1,2,3), (3,4,5)...]
                else:
                    return None
            except Exception as e:
                debug_log.exception(e)
                debug_log.info(cur)
                db.close()
                return None

    def get_slr_key(self, surrogate_id):
        # Now we fetch the SLR and put it to SLR_Tool
        slr_tool = SLR_tool()
        slr = self.get_slr(surrogate_id)
        slr_tool.slr = slr
        # Fetch key from SLR.
        keys = slr_tool.get_cr_keys()
        debug_log.info("Got following key(s) from SLR: {}".format(keys))
        sign_key = jwk.JWK(**keys[0])
        return sign_key

    def store_slr_JSON(self, json, slr_id, surrogate_id):
        """
        Store SLR into database
        :param surrogate_id:
        :param slr_id:
        :param json:
        :return:
        """
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info("Storing SLR '{}' belonging to surrogate_id '{}' with content:\n {}"
                       .format(slr_id, surrogate_id, json))
        cursor.execute("INSERT INTO storage (surrogate_id,json,slr_id) \
            VALUES (%s, %s, %s)", (surrogate_id, dumps(json), slr_id))
        db.commit()
        db.close()

    def store_ssr_JSON(self, json):
        """
        Store SSR into database
        :param record_id:
        :param surrogate_id:
        :param slr_id:
        :param json:
        :return:
        """
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()

        decoded_payload = base_token_tool.decode_payload(json["attributes"]["payload"])
        record_id = decoded_payload["record_id"]
        surrogate_id = decoded_payload["surrogate_id"]
        slr_id = decoded_payload["slr_id"]
        ssr = json["attributes"]
        debug_log.info("Got '{}' containing \n'{}' \nFor ssr.".format(type(ssr), ssr))
        sign_key = self.get_slr_key(surrogate_id)

        self.verify_JWS(ssr, sign_key)
        debug_log.info("SSR verified with key from associated SLR successfully.")


        debug_log.info("Storing SSR '{}' momentarily.\n {}".format(record_id, decoded_payload))
        prev_id = decoded_payload["prev_record_id"]
        if prev_id != "NULL":
            debug_log.info("Verifying SSR chain is unbroken.\n Looking up previous record '{}'".format(prev_id))
            prev_record = self.query_db("select record_id, json from ssr_storage where record_id = %s", (prev_id,))
            if prev_record is None:
                raise TypeError("Previous record_id is not found")  # Todo We make this basic check but is it enough?
            debug_log.info("Found record: \n{}".format(prev_record))

        debug_log.info("Storing SSR '{}' belonging to surrogate_id '{}' with content:\n {}"
                       .format(record_id, surrogate_id, json))
        cursor.execute("INSERT INTO ssr_storage (surrogate_id,json,record_id,slr_id,prev_record_id) \
            VALUES (%s, %s, %s, %s, %s)", (surrogate_id, dumps(json), record_id, slr_id, prev_id))
        db.commit()
        db.close()

    def verify_JWS(self, jws_to_verify, sign_key):
        debug_log.info("Verifying JWS: \n'{}'\n With key: {}".format(jws_to_verify, sign_key))
        # Create empty JWS object for the SSR
        json_web_signature = jws.JWS()
        if (isinstance(jws_to_verify, dict)):
            json_web_signature.deserialize(dumps(jws_to_verify))
        elif (isinstance(jws_to_verify, str)):
            json_web_signature = jws.JWS(jws_to_verify)

        # Verify the SSR with key from SLR
        json_web_signature.verify(sign_key)

    def verifyJWS(self, json_JWS):
        def verify(jws, header):
            try:
                sign_key = jwk.JWK(**header["jwk"])
                jws.verify(sign_key)
                return True
            except Exception as e:
                debug_log.info("JWS verification failed with:")
                debug_log.info(repr(e))

        try:

            json_web_signature = jws.JWS()
            if (isinstance(json_JWS, dict)):
                json_web_signature.deserialize(dumps(json_JWS))
            elif (isinstance(json_JWS, str)):
                json_web_signature = jws.JWS(json_JWS)
                json_JWS = loads(json_JWS)

            if json_JWS.get("header", False):  # Only one signature
                if verify(json_web_signature, json_JWS["header"]):
                    return True
                return False
            elif json_JWS.get("signatures", False):  # Multiple signatures
                signatures = json_JWS["signatures"]
                for signature in signatures:
                    if verify(json_web_signature, signature["header"]):
                        return True
            return False
        except Exception as e:
            debug_log.info("JWS verification failed with:")
            debug_log.info("M:", repr(e))
            return False

    def storeToken(self, DictionaryToStore):
        """
        Store token into database
        :param DictionaryToStore: Dictionary in form {"key" : "dict_to_store"}
        :return: 
        """
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        for key in DictionaryToStore:
            try:
                cursor.execute("INSERT INTO token_storage (cr_id,token) \
                    VALUES (%s, %s)", (key, dumps(DictionaryToStore[key])))
                db.commit()
            except IntegrityError as e:  # Rewrite incase we get new token.
                cursor.execute("UPDATE token_storage SET token=? WHERE cr_id=%s ;",
                               (dumps(DictionaryToStore[key]), key))
                db.commit()
        db.close()

    def lock_user(self, user_id):
        """
        Store user into DB while we are linking, preventing further service link attempts until previous one is finished.
        :param code: {code: "{}{}".format("!", code)}
        :return: None
        """
        # TODO: Refactor DB name from codes to userlock or something like that.
        # TODO: This naming is confusing, one can't know we're touching session_store with this function
        # let alone initiate it.
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        cursor.execute("INSERT INTO session_store (ID,code,surrogate_id) \
            VALUES (%s, %s, %s)", (user_id, user_id, user_id))
        db.commit()
        debug_log.info("Locking user_id({}) for SLR creation".format(user_id))
        db.close()


    def add_surrogate_id_to_user_id(self, user_id, surrogate_id):
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        cursor.execute("UPDATE session_store SET surrogate_id=%s WHERE ID=%s ;", (surrogate_id, user_id))
        db.commit()
        db.close()

    def add_code_to_surrogate_id(self, code, surrogate_id):
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        cursor.execute("UPDATE session_store SET code=%s WHERE surrogate_id=%s ;", (code, surrogate_id))
        #cursor.execute("UPDATE session_store SET surrogate_id=%s WHERE ID=%s ;", (surrogate_id, user_id))
        db.commit()
        db.close()


    def get_cr_json(self, cr_id):
        # TODO: query_db is not really optimal when making two separate queries in row.
        cr = self.query_db("select * from cr_storage where cr_id = %s;", (cr_id,))
        csr_id = self.get_latest_csr_id(cr_id)
        csr = self.query_db("select cr_id, json from csr_storage where csr_id = %s and cr_id = %s;", (csr_id, cr_id,))
        if cr is None or csr is None:
            raise IndexError("CR and CSR couldn't be found with given id ({})".format(cr_id))
        debug_log.info("Found CR ({}) and CSR ({})".format(cr, csr))
        cr_from_db = loads(cr)
        csr_from_db = loads(csr)
        combined = {"cr": cr_from_db, "csr": csr_from_db}

        return combined

    def get_source_cr(self, sink_cr_id):
        tool = CR_tool()
        sink_cr = self.get_cr_json(sink_cr_id)
        tool.cr = sink_cr
        source_cr_id = tool.get_source_cr_id()
        return source_cr_id

    def validate_cr(self, cr_id, surrogate_id):
        """
        Lookup and validate ConsentRecord based on given CR_ID
        :param cr_id:
        :return: CR if found and validated.
        """
        combined = self.get_cr_json(cr_id)
        debug_log.info("Constructing cr/csr structure for CR_Tool:")
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

        cr_verified = tool.verify_cr(keys)
        csr_verified = tool.verify_csr(keys)
        if not (cr_verified and csr_verified):
            raise ValueError("CR and CSR verification failed.")
        debug_log.info("Verified cr/csr ({}) for surrogate_id ({}) ".format(cr_id, surrogate_id))

        combined_decoded = dumps({"cr": tool.get_CR_payload(), "csr": tool.get_CSR_payload()}, indent=2)
        debug_log.info("Decoded cr/csr structure is:")
        debug_log.info(combined_decoded)
        # Check that state is "Active"
        state = tool.get_state()
        if state != "Active":
            raise ValueError("CR state is not 'Active' but ({})".format(state))

        # Check "Issued" timestamp
        time_now = int(time.time())
        issued = tool.get_issued()
        # issued = datetime.strptime(issued_in_cr, "%Y-%m-%dT%H:%M:%SZ")
        if time_now < issued:
            raise EnvironmentError("This CR is issued in the future!")
        debug_log.info("Issued timestamp is valid.")

        # Check "Not Before" timestamp
        not_before = tool.get_not_before()
        # not_before = datetime.strptime(not_before_in_cr, "%Y-%m-%dT%H:%M:%SZ")
        if time_now < not_before:
            raise EnvironmentError("This CR will be available in the future, not yet.")
        debug_log.info("Not Before timestamp is valid.")

        # Check "Not After" timestamp
        not_after = tool.get_not_after()
        # not_after = datetime.strptime(not_after_in_cr, "%Y-%m-%dT%H:%M:%SZ")
        if time_now > not_after:
            raise EnvironmentError("This CR is expired.")
        debug_log.info("Not After timestamp is valid.")
        # CR validated.

        debug_log.info("CR has been validated.")
        return loads(combined_decoded)

    def delete_session(self, code=None, user=None, surrogate_id=None):
        try:
            debug_log.info("Deleting session: {}".format(code))
            db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
            cursor = db.cursor()
            if code is None and surrogate_id is not None:
                cursor.execute("DELETE FROM session_store WHERE surrogate_id=%s ;", (surrogate_id,))
            elif code is None and user is not None:
                cursor.execute("DELETE FROM session_store WHERE ID=%s ;", (user,))
            else:
                cursor.execute("DELETE FROM session_store WHERE code=%s ;", (code,))
            db.commit()
            cursor.close()
            debug_log.info("Session {} deleted.".format(code))
        except Exception as e:
            debug_log.info("Something went wrong while deleting session {}.".format(code))
            debug_log.exception(e)

    def check_lock(self, user_id):
        """
        Verify that code is found in database
        :param user_id:
        :return: Boolean True if code is found in db. 
        """
        # TODO: Refactor db names
        user_id = self.query_db("select * from session_store where ID = %s;", (user_id,))
        if user_id is not None:
            return True
        return False

    def get_lastest_ssr_id(self, slr_id):
        # Picking first ssr_id since its previous record is "null"
        record_id = self.query_db(
            "select slr_id, record_id from ssr_storage where slr_id = %s and prev_record_id = 'null';",
            (slr_id,))
        debug_log.info("Picked first SSR_ID in search for latest ({})".format(record_id))
        # If first ssr_id is in others ssr's previous_record_id field then its not the latest.
        newer_ssr_id = self.query_db("select slr_id, record_id from ssr_storage where prev_record_id = %s;",
                                     (record_id,))
        debug_log.info("Later SSR_ID is ({})".format(newer_ssr_id))
        # If we don't find newer record but get None, we know we only have one ssr in our chain and latest in it is also the first.
        if newer_ssr_id is None:
            return record_id
        # Else we repeat the previous steps in while loop to go trough all records
        while True:  # TODO: We probably should see to it that this can't get stuck.
            try:
                newer_ssr_id = self.query_db("select slr_id, record_id from ssr_storage where prev_record_id = %s;",
                                             (record_id,))
                if newer_ssr_id is None:
                    debug_log.info("Latest SSR in our chain seems to be ({})".format(newer_ssr_id))
                    return record_id
                else:
                    record_id = newer_ssr_id
            except Exception as e:
                debug_log.exception(e)
                raise e

    def verify_slr_is_active(self, slr_id):
        ssr_id = self.get_lastest_ssr_id(slr_id)
        last_ssr_json = self.query_db("select slr_id, json from ssr_storage where record_id = %s;",
                                     (ssr_id,))
        debug_log.info("Fetched following JSON for SSR: \n{}".format(last_ssr_json))
        ssr_json = loads(last_ssr_json)
        decoded_payload = base_token_tool.decode_payload(ssr_json["attributes"]["payload"])
        debug_log.info("Decoded SSR payload: \n{}".format(dumps(decoded_payload, indent=2)))
        status = decoded_payload["sl_status"]
        if status == "Active":
            return True
        return False


    def verifySurrogate(self, code, surrogate):
        """
        Verify that surrogate id matches code in database
        :param code: 
        :param surrogate: surrogate_id
        :return: Boolean True if surrogate_id matches code
        """
        code = self.query_db("select * from session_store where code = %s AND surrogate_id = %s;", (code, surrogate))
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

    def get_surrogate_from_cr_id(self, cr_id):
        storage_row = self.query_db("select cr_id,surrogate_id from cr_storage where cr_id = %s;", (cr_id,))
        debug_log.info("Found surrogate_id {}".format(storage_row))
        surrogate_from_db = storage_row
        return surrogate_from_db

    def get_token(self, cr_id):
        """
        Fetch token for given cr_id from the database
        :param cr_id: cr_id
        :return: Return Token made for given cr_id or None
        """
        storage_row = self.query_db("select * from token_storage where cr_id = %s;", (cr_id,))
        token_from_db = loads(loads(storage_row))
        return token_from_db

    def storeCR_JSON(self, DictionaryToStore):
        """
        Store CR into database
        :param DictionaryToStore: Dictionary in form {"key" : "dict_to_store"}
        :return: None
        """
        debug_log.info("Got '{}' to store as CR".format(DictionaryToStore))
        cr_id = DictionaryToStore["cr_id"]
        rs_id = DictionaryToStore["rs_id"]
        surrogate_id = DictionaryToStore["surrogate_id"]
        slr_id = DictionaryToStore["slr_id"]
        json = DictionaryToStore["json"]

        # Fetch key from SLR
        sign_key = self.get_slr_key(surrogate_id)

        cr_json = json.get("attributes", None)
        if cr_json is None:
            cr_json = json

        # Verify JWS is signed appropriately
        self.verify_JWS(cr_json, sign_key)

        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info("Storing following CR structure:")
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
            raise DetailedHTTPException(detail={"msg": "Adding CR to the database has failed.", },
                                        title="Failure in CR storage", exception=e)

    def storeCSR_JSON(self, DictionaryToStore):
        """
        Store CSR into database
        :param DictionaryToStore: Dictionary in form {"key" : "dict_to_store"}
        :return: None
        """
        debug_log.info("Got '{}' to store as CSR".format(DictionaryToStore))
        cr_id = DictionaryToStore["cr_id"]
        csr_id = DictionaryToStore["csr_id"]
        consent_status = DictionaryToStore["consent_status"]
        surrogate_id = DictionaryToStore["surrogate_id"]
        previous_record_id = DictionaryToStore["previous_record_id"]
        json = DictionaryToStore["json"]

        # Fetch key from SLR
        sign_key = self.get_slr_key(surrogate_id)
        csr_json = json.get("attributes", None)
        if csr_json is None:
            csr_json = json

        # Verify JWS is signed appropriately
        self.verify_JWS(csr_json, sign_key)



        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info("Storing following csr structure:")
        debug_log.info(DictionaryToStore)
        # debug_log.info(key)
        try:
            cursor.execute("INSERT INTO csr_storage (cr_id, csr_id, previous_record_id, consent_status, surrogate_id, json) \
                VALUES (%s, %s, %s, %s, %s, %s)",
                           [cr_id, csr_id, previous_record_id, consent_status, surrogate_id, dumps(json)])
            db.commit()
        except IntegrityError as e:
            # db.execute("UPDATE csr_storage SET json=? WHERE cr_id=? ;", [dumps(DictionaryToStore[key]), key])
            # db.commit()
            db.rollback()
            raise DetailedHTTPException(detail={"msg": "Adding CSR to the database has failed.", },
                                        title="Failure in CSR storage", exception=e)

    def get_active_csr(self, cr_id):
        csr = self.query_db("select cr_id, json from csr_storage where cr_id = %s and consent_status = 'Active';",
                            (cr_id,))
        debug_log.info("Active csr is: {}".format(csr))
        return loads(csr)

    def get_latest_csr_id(self, cr_id):
        # Picking first csr_id since its previous record is "null"
        csr_id = self.query_db(
            "select cr_id, csr_id from csr_storage where cr_id = %s and previous_record_id = 'null';",
            (cr_id,))
        debug_log.info("Picked first CSR_ID in search for latest ({})".format(csr_id))
        # If first csr_id is in others csr's previous_record_id field then its not the latest.
        newer_csr_id = self.query_db("select cr_id, csr_id from csr_storage where previous_record_id = %s;",
                                     (csr_id,))
        debug_log.info("Later CSR_ID is ({})".format(newer_csr_id))
        # If we don't find newer record but get None, we know we only have one csr in our chain and latest in it is also the first.
        if newer_csr_id is None:
            return csr_id
        # Else we repeat the previous steps in while loop to go trough all records
        while True:  # TODO: We probably should see to it that this can't get stuck.
            try:
                newer_csr_id = self.query_db("select cr_id, csr_id from csr_storage where previous_record_id = %s;",
                                             (csr_id,))
                if newer_csr_id is None:
                    debug_log.info("Latest CSR in our chain seems to be ({})".format(newer_csr_id))
                    return csr_id
                else:
                    csr_id = newer_csr_id
            except Exception as e:
                debug_log.exception(e)
                raise e

    def introspection(self, cr_id, operator_url):
        # Get our latest csr_id

        # We send cr_id to Operator for inspection.
        # TODO: Where do we get these paths?
        req = get(operator_url + "/api/1.3/cr" + "/introspection/{}".format(cr_id))
        debug_log.info(req.status_code)
        debug_log.info(req.content)
        if req.ok:
            csr_id = loads(req.content)["csr_id"]
            # This is the latest csr we have verifiable chain for.
            latest_csr_id = self.get_latest_csr_id(cr_id)
            debug_log.info("Comparing our latest csr_id ({}) to ({})".format(latest_csr_id, csr_id))
            if csr_id == latest_csr_id:
                debug_log.info("Verified we have latest csr.")
                status = self.query_db("select cr_id, consent_status from csr_storage where csr_id = %s;"
                                       , (latest_csr_id,))
                return status
            else:
                debug_log.info("Our csr({}) is outdated!".format(latest_csr_id))
                req = get(
                    operator_url + "/api/1.3/cr" + "/consent/{}/missing_since/{}".format(cr_id, latest_csr_id))
                if req.ok:
                    decode_payload = base_token_tool.decode_payload
                    content = loads(req.content)
                    debug_log.info("We got: \n{}".format(content))
                    slr_id = self.query_db("select cr_id, slr_id from cr_storage where cr_id = %s;"
                                           , (cr_id,))
                    rs_id = self.query_db("select cr_id, rs_id from cr_storage where cr_id = %s;"
                                          , (cr_id,))
                    for csr in content["missing_csr"]["data"]:
                        if not isinstance(csr, dict):
                            csr = loads(csr)
                        decoded_payload = decode_payload(csr["attributes"]["csr"]["payload"])
                        store_dict = {
                            "rs_id": rs_id,
                            "csr_id": decoded_payload["record_id"],
                            "consent_status": decoded_payload["consent_status"],
                            "previous_record_id": decoded_payload["prev_record_id"],
                            "cr_id": decoded_payload["cr_id"],
                            "surrogate_id": decoded_payload["surrogate_id"],
                            "slr_id": slr_id,
                            "json": csr  # possibly store the base64 representation
                        }
                        debug_log.info("Storing CSR: \n{}".format(dumps(store_dict, indent=2)))
                        self.storeCSR_JSON(store_dict)
                    debug_log.info("Stored any missing csr's to DB")
                    latest_csr_id = self.get_latest_csr_id(cr_id)
                    status = self.query_db("select cr_id, consent_status from csr_storage where csr_id = %s;"
                                           , (latest_csr_id,))
                    debug_log.info("Our latest csr id now ({}) with status ({})".format(latest_csr_id, status))

                    debug_log.info("Introspection done successfully.")
                    return status

                else:
                    raise ValueError("Request to get missing csr's failed with ({}) and reason ({}), content:\n{} "
                                     .format(req.status_code, req.reason, dumps(loads(req.content), indent=2)))

        else:
            raise LookupError("Unable to perform introspection.")

    def validate_request_from_ui(self, cr, data_set_id, rs_id):
        debug_log.info("CR passed to validate_request_from_ui:")
        debug_log.info(type(cr))
        debug_log.info(cr)

        # The rs_id is urlencoded, do the same to one fetched from cr
        rs_id_in_cr = urllib.quote_plus(cr["cr"]["common_part"]["rs_id"])
        debug_log.info("Found rs_id ({}) from cr".format(rs_id_in_cr))
        # Check that rs_description field contains rs_id
        debug_log.info("rs_id in cr({}) and from ui({})".format(rs_id_in_cr, rs_id))
        if (rs_id != rs_id_in_cr):
            raise ValueError("Given rs_id doesn't match CR")
        debug_log.info("RS_ID checked successfully")
        # Check that rs_description field contains data_set_id (Optional?)
        distribution_urls = []
        if data_set_id is not None:
            datasets = cr["common_part"]["rs_description"]["resource_set"]["dataset"]
            for dataset in datasets:
                if dataset["dataset_id"] == data_set_id:
                    distribution_urls.append(dataset["distribution_url"])
        else:
            datasets = cr["cr"]["common_part"]["rs_description"]["resource_set"]["dataset"]
            for dataset in datasets:
                distribution_urls.append(dataset["distribution_url"])
        debug_log.info("Got following distribution urls")
        debug_log.info(distribution_urls)
        # Request from UI validated.
        debug_log.info("Request from UI validated.")
        return distribution_urls

    def validate_authorization_token(self, cr_id, surrogate_id, our_key):
        # slr = self.get_slr(surrogate_id)
        # slr_tool = SLR_tool()
        # slr_tool.slr = slr
        # key = slr_tool.get_operator_key()
        token = self.get_token(cr_id)
        # debug_log.info("Fetched key({}) and token({}).".format(key, token))
        jws_holder = jwt.JWS()
        jws_holder.deserialize(raw_jws=token["auth_token"])
        auth_token_payload = loads(jws_holder.__dict__["objects"]["payload"])
        debug_log.info("Decoded Auth Token\n{}".format(dumps(auth_token_payload, indent=2)))
        now = time.time()
        if auth_token_payload["exp"] < now:
            raise ValueError("Token is expired.")
        if auth_token_payload["nbf"] > now:
            raise TypeError("Token used too soon.")
        # debug_log.info(aud)
        return token

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

        debug_log.info("API COMPILATION:")
        debug_log.info(req_msg)
        debug_log.info(resp_msg)
        return resp
    return loggedfunc



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

import logging
from json import dumps


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

    def reply_from(self, origin="Origin_Name", msg=""):
        return self.seq_tool(msg=msg, to=self.name, dotted=True, alt_name=origin)

    def message_from(self, origin="Origin_Name", msg=""):
        return self.seq_tool(msg=msg, to=self.name, dotted=False, alt_name=origin)

    def activate(self):
        return self.seq_form("activate " + self.name)

    def deactivate(self):
        return self.seq_form("deactivate " + self.name)

    def seq_tool(self, msg=None, to="Change_Me", box=False, dotted=False, alt_name=False):
        name = self.name
        if alt_name:
            name = alt_name
        if box:
            form = 'Note over {}: {}'.format(name, msg)
            return self.seq_form(form, )
        elif dotted:
            form = "{}-->{}: {}".format(name, to, msg)
            return self.seq_form(form)
        else:
            form = "{}->{}: {}".format(name, to, msg)
            return self.seq_form(form)

    def opt(self, op_name="", end=False):
        if end:
            return self.seq_form("end")
        return self.seq_form("opt "+op_name)

    def seq_form(self, line):
        self.logger.info(dumps({"seq": line, "time": time.time()}))
        return {"seq": {}}

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
        # Here you can see the structure this tool handles
        # Do note this default value should be re-assigned before use
        # TODO: This "example" is really outdated.
        self.slr = {"code": "486b01cb-518a-4838-be63-624f0d86a2a1",
                    "data": {
                        "surrogate_id": "e15053fd-0808-4125-9acf-f0647d62a2bb_486b01cb-518a-4838-be63-624f0d86a2a1",
                        "slr": {
                            "attributes": {
                                "slr": {
                                    "signatures": [
                                        {
                                            "header": {
                                                "kid": "acc-kid-a40b9976-916a-4a13-a149-7241ce56abb4"

                                            },
                                            "protected": "eyJhbGciOiAiRVMyNTYifQ",
                                            "signature": "RE2o3P85Zcss3PD6uKHgr7Mk2UI-wFmv1IthtjWIbEJsyF2OBwmpeDafhbmE1sDy6EOL6mnm4iLYd3VqaG-Jhg"

                                        },
                                        {
                                            "header": {
                                                "jwk": {
                                                    "kid": "SRVMGNT-RSA-512",
                                                    "e": "AQAB",
                                                    "kty": "RSA",
                                                    "n": "yGgsP9cWMiPPmgOQ0JtYSw6zwuDou8AGAyDutv5pLw5ivz6xoLhZM-iQWF7EsrEGtSrQNyYLs2Vs-JqmntPjHQ"

                                                },
                                                "kid": "SRVMGMNT-CHANGE_ME"

                                            },
                                            "protected": "eyJhbGciOiAiUlMyNTYifQ",
                                            "signature": "VLpAmxZoNQVP3ilGoMMsGGro23kPiISxqqyJsOi7EmbSoHnHWCKktJyqM5xsiNkfyGnfIoKTCowsAamNS5ymgQ"

                                        }

                                    ],
                                    "payload": "eyJvcGVyYXRvcl9pZCI6ICJPcGVyYXRvcjExMiIsICJzdXJyb2dhdGVfaWQiOiAiZTE1MDUzZmQtMDgwOC00MTI1LTlhY2YtZjA2NDdkNjJhMmJiXzQ4NmIwMWNiLTUxOGEtNDgzOC1iZTYzLTYyNGYwZDg2YTJhMSIsICJsaW5rX2lkIjogIjFhMzYxYjE1LTEyODYtNGQyNi1iNzFiLWYwODRlZjE3ZGY0MSIsICJvcGVyYXRvcl9rZXkiOiB7ImtpZCI6ICJBQ0MtSUQtUkFORE9NIiwgImUiOiAiQVFBQiIsICJrdHkiOiAiUlNBIiwgIm4iOiAidG1obGFQVXdKZ280eVNUTXJUR0ZGeWJWeEsyOHVER3RKU0ZEZEdrM2JheFRXbWdmSzBDNkRNcXc1bHFwLUVYVE1UUmZJcU1iZE1jRG1VTm55SnBRMXcifSwgInZlcnNpb24iOiAiMS4yIiwgImNyX2tleXMiOiBbeyJ5IjogImRha3dlMlBwbWxkbGFjbnBvSGE1bHZrRDFabFhURnZXYTNlYURvRmZWaUkiLCAieCI6ICJoanFnTGlvRS1Kek51QVdFOVp3ZUE5QkRiNWxTU3pVUDZ6eHB4WlZyNG53IiwgImNydiI6ICJQLTI1NiIsICJrdHkiOiAiRUMiLCAia2lkIjogImFjYy1raWQtYTQwYjk5NzYtOTE2YS00YTEzLWExNDktNzI0MWNlNTZhYmI0In1dLCAic2VydmljZV9pZCI6ICI1ODJmMmJmNTBjZjJmNDY2M2VjNGYwMWYiLCAiaWF0IjogMTQ4MTEwNjg4Nn0"

                                }

                            },
                            "type": "ServiceLinkRecord",
                            "id": "1a361b15-1286-4d26-b71b-f084ef17df41"

                        },
                        "ssr": {
                            "attributes": {
                                "slsr": {
                                    "header": {
                                        "kid": "acc-kid-a40b9976-916a-4a13-a149-7241ce56abb4"

                                    },
                                    "protected": "eyJhbGciOiAiRVMyNTYifQ",
                                    "payload": "eyJzbHJfaWQiOiAiMWEzNjFiMTUtMTI4Ni00ZDI2LWI3MWItZjA4NGVmMTdkZjQxIiwgImFjY291bnRfaWQiOiAiMiIsICJzdXJyb2dhdGVfaWQiOiAiZTE1MDUzZmQtMDgwOC00MTI1LTlhY2YtZjA2NDdkNjJhMmJiXzQ4NmIwMWNiLTUxOGEtNDgzOC1iZTYzLTYyNGYwZDg2YTJhMSIsICJzbF9zdGF0dXMiOiAiQWN0aXZlIiwgInZlcnNpb24iOiAiMS4yIiwgInJlY29yZF9pZCI6ICI0MmRkNjBkYy1iZGUzLTQwZmMtYTM4Yi04NjJhNzllMDQyYjgiLCAiaWF0IjogMTQ4MTEwNjg4NywgInByZXZfcmVjb3JkX2lkIjogIk5VTEwifQ",
                                    "signature": "824jlcq5oKa2-xk9mswlyrgvhWQbkC3NbgeY0GT-IXvK9uxeMkxkHY0AQa1usan3WP6ee5SMbKClt7xRV_Q5oQ"

                                }

                            },
                            "type": "ServiceLinkStatusRecord",
                            "id": "42dd60dc-bde3-40fc-a38b-862a79e042b8"

                        }

                    }

                    }

    def get_SLR_payload(self):
        debug_log.info("SLR in tool is:\n {}".format(self.slr))
        base64_payload = self.slr["attributes"]["payload"]
        debug_log.info("Decoding SLR payload:")
        payload = self.decode_payload(base64_payload)
        return payload

    def get_SSR_payload(self):
        base64_payload = self.slr["attributes"]["payload"]
        debug_log.info("Decoding SSR payload:")
        payload = self.decode_payload(base64_payload)
        return payload

    def get_token_key(self):
        return self.get_SLR_payload()["token_key"]

    def get_operator_key(self):
        return self.get_SLR_payload()["operator_key"]

    def get_cr_keys(self):
        return self.get_SLR_payload()["cr_keys"]


from jwcrypto import jwk, jws


class CR_tool(base_token_tool):
    def __init__(self):
        # This is the kind of structure this tool expects to work with
        # csr and cr are both jws structures in the long (not compact) form.
        self.cr = {
            "csr": {},
            "cr": {}
        }

    def get_CR_payload(self):
        base64_payload = self.cr["cr"]["payload"]
        payload = self.decode_payload(base64_payload)
        return payload

    def get_CSR_payload(self):
        base64_payload = self.cr["csr"]["payload"]
        payload = self.decode_payload(base64_payload)
        return payload

    def get_cr_id_from_csr(self):
        return self.get_CSR_payload()["cr_id"]

    def get_csr_id(self):
        return self.get_CSR_payload()["record_id"]  # Perhaps this could just be csr_id

    def get_consent_status(self):
        return self.get_CSR_payload()["consent_status"]

    def get_prev_record_id(self):
        return self.get_CSR_payload()["prev_record_id"]

    def get_cr_id_from_cr(self):
        return self.get_CR_payload()["common_part"]["cr_id"]

    def cr_id_matches_in_csr_and_cr(self):
        return self.get_cr_id_from_cr() == self.get_cr_id_from_csr()

    def get_usage_rules(self):
        return self.get_CR_payload()["role_specific_part"]["usage_rules"]

    def get_pop_key(self):
        return self.get_CR_payload()["role_specific_part"]["pop_key"]

    def get_source_cr_id(self):
        return self.get_CR_payload()["role_specific_part"]["source_cr_id"]

    def get_slr_id(self):
        return self.get_CR_payload()["common_part"]["slr_id"]

    def get_issued(self):
        return self.get_CR_payload()["common_part"]["iat"]

    def get_not_before(self):
        return self.get_CR_payload()["common_part"]["nbf"]

    def get_not_after(self):
        return self.get_CR_payload()["common_part"]["exp"]

    def get_rs_id(self):
        return self.get_CR_payload()["common_part"]["rs_id"]

    def get_state(self):
        return self.get_CSR_payload()["consent_status"]

    def get_subject_id(self):
        return self.get_CR_payload()["common_part"]["subject_id"]

    def get_surrogate_id(self):
        return self.get_CR_payload()["common_part"]["surrogate_id"]

    def get_role(self):
        return self.get_CR_payload()["common_part"]["role"]

    def verify_cr(self, keys):
        debug_log.info("CR in object:\n{}".format(dumps(self.cr, indent=2)))
        for key in keys:
            cr_jwk = jwk.JWK(**key)
            cr_jws = jws.JWS()
            cr = self.cr["cr"]
            cr_jws.deserialize(dumps(cr))

            try:
                cr_jws.verify(cr_jwk)
                return True
            except Exception as e:
                debug_log.info(
                    "FAILED key verification for CR: \n({})\n WITH KEY: \n({})".format(cr, cr_jwk.export_public()))
                debug_log.exception(e)
                # print(repr(e))
                # return False
        return False

    def verify_csr(self, keys):
        for key in keys:
            cr_jwk = jwk.JWK(**key)
            csr_jws = jws.JWS()
            csr = self.cr["csr"]
            csr_jws.deserialize(dumps(csr))
            try:
                csr_jws.verify(cr_jwk)
                return True
            except Exception as e:
                debug_log.info(
                    "FAILED key verification for CSR: \n({})\n WITH KEY: \n({})".format(csr, cr_jwk.export_public()))
                debug_log.exception(e)
                pass
                # print(repr(e))
                # return False
        return False


# crt = CR_tool()
# print (dumps(crt.get_CR_payload(), indent=2))
# print (dumps(crt.get_CSR_payload(), indent=2))
# print(crt.get_role())
# print(crt.get_cr_id())
# print(crt.get_usage_rules())
# print(crt.get_surrogate_id())
from jwcrypto import jwt
from jwcrypto.jwt import JWTExpired


class Token_tool:
    def __init__(self):
        #  Replace token.
        self.token = {
            "auth_token": "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOlt7ImRhdGFzZXRfaWQiOiJTdHJpbmciLCJkaXN0cmlidXRpb25faWQiOiJTdHJpbmcifV0sImV4cCI6IjIwMTYtMTEtMDhUMTM6MzA6MjUgIiwiaWF0IjoiMjAxNi0xMC0wOVQxMzozMDoyNSAiLCJpc3MiOnsiZSI6IkFRQUIiLCJraWQiOiJBQ0MtSUQtUkFORE9NIiwia3R5IjoiUlNBIiwibiI6InRtaGxhUFV3SmdvNHlTVE1yVEdGRnliVnhLMjh1REd0SlNGRGRHazNiYXhUV21nZkswQzZETXF3NWxxcC1FWFRNVFJmSXFNYmRNY0RtVU5ueUpwUTF3In0sImp0aSI6Ijc5ZmI3NDg0LTE2YjYtNDEzYy04ZGI0LWZlMjcwYjg4Y2UxNiIsIm5iZiI6IjIwMTYtMTAtMDlUMTM6MzA6MjUgIiwicnNfaWQiOiJodHRwOi8vc2VydmljZV9jb21wb25lbnRzOjcwMDB8fDljMWYxNTdkLWM4MWEtNGY1Ni1hZmYxLTc2MWZjNTVhNDBkOSIsInN1YiI6eyJlIjoiQVFBQiIsImtpZCI6IlNSVk1HTlQtUlNBLTUxMiIsImt0eSI6IlJTQSIsIm4iOiJ5R2dzUDljV01pUFBtZ09RMEp0WVN3Nnp3dURvdThBR0F5RHV0djVwTHc1aXZ6NnhvTGhaTS1pUVdGN0VzckVHdFNyUU55WUxzMlZzLUpxbW50UGpIUSJ9fQ.s1KOu1Q_ifNEnmBQ6QcmNxd0Oy1Fxp-z_4hsCI5fNfOa5vtWai68_OKN_NoUjtqUCy-CJcLHnGGoxTh_vHcjtg"}
        #  Replace key.
        self.key = None

    def decode_payload(self, payload):
        key = jwk.JWK()
        key.import_key(**self.key)
        token = jwt.JWT()
        # This step actually verifies the signature, the format and timestamps.
        try:
            token.deserialize(self.token["auth_token"], key)
        except JWTExpired as e:
            debug_log.exception(e)
            # TODO: get new auth token and start again.
            raise e
        claims = loads(token.claims)
        debug_log.info("Decoded following claims from token:")
        debug_log.info(dumps(claims, indent=2))
        # payload = loads(loads(content.decode('utf-8')))
        return claims

    def get_token(self):
        debug_log.info("Fetching token..")
        decoded_token = self.decode_payload(self.token["auth_token"])
        debug_log.info("Got following token:")
        debug_log.info(dumps(decoded_token, indent=2))
        return decoded_token

    def verify_token(self,
                     our_key):  # TODO: Get some clarification what we want to verify now that sub field doesn't contain key.
        debug_log.info("Verifying token..\nOur key is:")
        debug_log.info(our_key)
        debug_log.info(type(our_key))

        if self.key is None:
            raise UnboundLocalError("Set Token_tool objects key variable to Operator key before use.")
        token = self.get_token()
        kid = token["cnf"]["kid"]
        source_cr_id = token["pi_id"]
        debug_log.info("Source CR id is:")
        debug_log.info(type(source_cr_id))
        debug_log.info(source_cr_id)
        # debug_log.info(our_key)
        if cmp(source_cr_id, kid) != 0:
            raise ValueError("JWK's didn't match.")

        # TODO: Figure out beter way to return aud
        return token
