# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import time
import traceback
from base64 import urlsafe_b64decode as decode
from json import loads, dumps
from uuid import uuid4 as guid
from hashlib import sha256

from flask import request, abort, Blueprint, current_app, redirect
from flask_cors import CORS
from flask_restful import Resource, Api, reqparse
from jwcrypto import jws, jwk
from requests import post

from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_srv import Helpers, Sequences, api_logging

api_Service_Mgmnt = Blueprint("api_Service_Mgmnt", __name__)

CORS(api_Service_Mgmnt)
api = Api()
api.init_app(api_Service_Mgmnt)
logger = logging.getLogger("sequence")
debug_log = logging.getLogger("debug")

sq = Sequences("Service_Components Mgmnt")

'''

'''


def timeme(method):
    def wrapper(*args, **kw):
        startTime = int(round(time.time() * 1000))
        result = method(*args, **kw)
        endTime = int(round(time.time() * 1000))

        debug_log.info("{}{}".format(endTime - startTime, 'ms'))
        return result

    return wrapper


class GenerateSurrogateId(Resource):
    def __init__(self):
        super(GenerateSurrogateId, self).__init__()
        keysize = current_app.config["KEYSIZE"]
        cert_key_path = current_app.config["CERT_KEY_PATH"]
        self.helpers = Helpers(current_app.config)
        self.service_key = self.helpers.get_key()
        self.is_sink = current_app.config["IS_SINK"]
        self.is_source = current_app.config["IS_SOURCE"]
        self.service_id = current_app.config["SERVICE_ID"]
        self.service_url = current_app.config["SERVICE_URL"]
        self.operator_url = current_app.config["OPERATOR_URL"]
        self.lock_wait_time = current_app.config["LOCK_WAIT_TIME"]


    @timeme
    @error_handler
    @api_logging
    def post(self):
        try:
            # TODO: Verify this requests comes from Service Mockup(Is this our responsibility?)
            # This is now the point we want to double check that similar flow is not going on already for said user.
            user_id = request.json["user_id"]
            operator_id = request.json["operator_id"]

            sq.task("Checking if user_id is locked already.")
            user_is_locked = self.helpers.check_lock(user_id)
            if user_is_locked:
                time.sleep(self.lock_wait_time)
                user_is_locked = self.helpers.check_lock(user_id)
            if user_is_locked:
                raise DetailedHTTPException(status=503,
                                             detail={"msg": "Another SLR linking is in process, please try again once "
                                                            "linking is over"},
                                             title="User_id locked for SLR creation.")
            else:
                sq.task("Locking user_id.")
                self.helpers.lock_user(user_id)

                sq.task("Generate surrogate_id.")
                # TODO: Some logic to surrogate_id's?
                # surrogate_id is meant to be unique between operator and service.
                surrogate_id = sha256("{}_{}_{}".format(self.service_id, user_id, operator_id)).hexdigest()

                # Store surrogate_id to database
                self.helpers.add_surrogate_id_to_user_id(user_id, surrogate_id)

                sq.send_to("Service_Mockup", "Send surrogate_id to Service_Mockup")
                content_json = {"surrogate_id": surrogate_id}
                return content_json, 201
        except DetailedHTTPException as e:
            debug_log.exception(e)
            self.helpers.delete_session(user=user_id)
            e.trace = traceback.format_exc(limit=100).splitlines()
            raise e
        except Exception as e:
            debug_log.exception(e)
            self.helpers.delete_session(user=user_id)
            raise DetailedHTTPException(exception=e,
                                        detail="Something failed in generating and delivering Surrogate_ID.",
                                        trace=traceback.format_exc(limit=100).splitlines())


class StartServiceLinking(Resource):
    def __init__(self):
        super(StartServiceLinking, self).__init__()
        self.helpers = Helpers(current_app.config)
        self.service_key = self.helpers.get_key()
        self.is_sink = current_app.config["IS_SINK"]
        self.is_source = current_app.config["IS_SOURCE"]
        self.service_url = current_app.config["SERVICE_URL"]
        self.operator_url = current_app.config["OPERATOR_URL"]
        self.lock_wait_time = current_app.config["LOCK_WAIT_TIME"]

        self.parser = reqparse.RequestParser()
        self.parser.add_argument('code', type=str, help='session code')
        self.parser.add_argument('operator_id', type=str, help='Operator UUID.')
        self.parser.add_argument('return_url', type=str, help='Url safe Base64 coded return url.')
        self.parser.add_argument('surrogate_id', type=str, help="surrogate ID")
        # TODO: Verify service_id is unnecessary.
        #self.parser.add_argument('service_id', type=str, help="Service's ID")  # Seems unnecessary to the flow.

    @error_handler
    @api_logging
    def post(self):
        args = self.parser.parse_args()
        debug_log.debug("StartServiceLinking got parameter:\n {}".format(args))
        data = {"surrogate_id": args["surrogate_id"], "code": args["code"]}

        sq.task("Link code to generated surrogate_id")
        self.helpers.add_code_to_surrogate_id(args["code"], args["surrogate_id"])

        if self.is_sink:
            data["token_key"] = self.service_key["pub"]  # TODO: Are we implementing according to 1.3 in such way that we have
            # operator, service, user specific pop keys?
        sq.send_to("Operator_Components Mgmnt", "Send Operator_Components request to make SLR")
        endpoint = "/api/1.3/slr/link"  # Todo: this needs to be fetched from somewhere
        result = post("{}{}".format(self.operator_url, endpoint), json=data)
        debug_log.info("####slr/link reply from operator: {}\n{}".format(result.status_code, result.text))
        if result.ok:
            self.helpers.delete_session(args["code"])
            return result.text, 201
        elif result.status_code == 500:
            self.helpers.delete_session(args["code"])
            raise DetailedHTTPException(status=500,
                                        detail={"msg": "Linking Service has failed due to server side issue."},
                                        title="Could not link Service.")
        else:
            self.helpers.delete_session(args["code"])
            raise DetailedHTTPException(status=result.status_code,
                                        detail={
                                            "msg": "Something went wrong while posting to Operator_SLR for /link",
                                            "Error from Operator_SLR": loads(result.text)},
                                        title=result.reason)


def header_fix(malformed_dictionary):  # We do not check if its malformed, we expect it to be.
    if malformed_dictionary.get("signature", False):
        malformed_dictionary["header"] = loads(malformed_dictionary["header"])
        return malformed_dictionary
    elif malformed_dictionary.get("signatures", False):
        sigs = malformed_dictionary["signatures"]
        for signature in sigs:
            if isinstance(signature["header"], str):
                signature["header"] = loads(signature["header"])
        return malformed_dictionary
    raise ValueError("Received dictionary was not expected type.")

class StoreSSR(Resource):
    def __init__(self):
        super(StoreSSR, self).__init__()
        config = current_app.config
        self.helpers = Helpers(config)
        self.service_url = config["SERVICE_URL"]


    @timeme
    @error_handler
    @api_logging
    def post(self):
        # TODO: This is as naive as it gets, needs some verifications regarding ssr,
        # or are we leaving this to firewalls, eg. Only this host(operator) can use this endpoint.
        try:
            self.helpers.store_ssr_JSON(json=request.json["data"])
            endpoint = "/api/1.3/slr/store_ssr"
            debug_log.info("Posting SLR for storage in Service Mockup")
            result = post("{}{}".format(self.service_url, endpoint), json=request.json)  # Send copy to Service_Components
            return {"id":request.json["data"]["id"]}, 201
        except Exception as e:
            debug_log.exception(e)
            raise e



class StoreSLR(Resource):
    def __init__(self):
        super(StoreSLR, self).__init__()
        config = current_app.config
        keysize = config["KEYSIZE"]
        cert_key_path = config["CERT_KEY_PATH"]
        self.helpers = Helpers(config)
        self.service_key = self.helpers.get_key()

        self.protti = self.service_key["prot"]
        self.headeri = self.service_key["header"]

        self.service_url = config["SERVICE_URL"]
        self.operator_url = config["OPERATOR_URL"]


    @timeme
    @error_handler
    @api_logging
    def post(self):

        def decode_payload(payload):
            sq.task("Fix possible incorrect padding in payload")
            payload += '=' * (-len(payload) % 4)  # Fix incorrect padding of base64 string.
            debug_log.info("After padding fix :{}".format(payload))

            sq.task("Decode SLR payload and store it into object")
            debug_log.info(payload.encode())
            content = decode(payload.encode())

            sq.task("Load decoded payload as python dict")
            payload = loads(content.decode("utf-8"))
            debug_log.info("Decoded SLR payload:")
            debug_log.info(type(payload))
            debug_log.info(dumps(payload, indent=2))
            return payload

        try:
            sq.task("Load SLR to object")
            slr = request.json["slr"]
            debug_log.info("SLR STORE:\n", slr)

            sq.task("Load slr payload as object")
            payload = slr["payload"]
            debug_log.info("Before padding fix:{}".format(payload))

            payload = decode_payload(payload)

            sq.task("Fetch surrogate_id from decoded SLR payload")
            surrogate_id = payload["surrogate_id"].encode()

            sq.task("Load code from json payload")
            code = request.json["data"]["code"].encode()
            debug_log.info("SLR payload contained code: {}".format(code))

            sq.task("Verify surrogate_id and code")
            debug_log.info("Surrogate {} has been verified for code {}.".format(self.helpers.verifySurrogate(code, surrogate_id), code))

        except Exception as e:
            raise DetailedHTTPException(title="Verifying Surrogate ID failed",
                                        exception=e,
                                        trace=traceback.format_exc(limit=100).splitlines())

        try:
            sq.task("Create empty JSW object")
            jwssa = jws.JWS()
            debug_log.info("SLR Received:\n"+(dumps(slr, indent=2)))

            sq.task("Deserialize slr to JWS object created before")
            jwssa.deserialize(dumps(slr))

            sq.task("Load JWK used to sign JWS from the slr payload's cr_keys field into an object")
            sign_key = jwk.JWK(**payload["cr_keys"][0])

            sq.task("Verify SLR was signed using the key shipped with it")
            debug_log.info(self.helpers.verifyJWS(slr))
            verify = jwssa.verify(sign_key)  # Verifying changes the state of this object
        except Exception as e:
            raise DetailedHTTPException(title="Verifying JWS signature failed",
                                        exception=e,
                                        trace=traceback.format_exc(limit=100).splitlines())

        try:
            sq.task("Fix possible serialization errors in JWS")
            faulty_JSON = loads(jwssa.serialize(compact=False))  # For some reason serialization messes up "header" from "header": {} to "header": "{}"
            faulty_JSON["header"] = faulty_JSON["header"]

            sq.task("Add our signature in the JWS")
            key = jwk.JWK(**self.service_key["key"])
            jwssa.add_signature(key, header=dumps(self.headeri), protected=dumps(self.protti))

            sq.task("Fix possible header errors")
            fixed = header_fix(loads(jwssa.serialize(compact=False)))
            debug_log.info("{}\n{}\n{}".format("Verified and Signed Signature:\n", dumps(fixed, indent=3),
                                               "\n###### END OF SIGNATURE #######"))

            sq.task("Create template for verifying JWS at Operator_Components")
            req = {"data": {"code": code}, "slr": fixed}
            debug_log.info(dumps(req, indent=2))
        except Exception as e:
            raise DetailedHTTPException(exception=e,
                                        title="JWS fix and subsequent signing of JWS with out key failed.",
                                        trace=traceback.format_exc(limit=100).splitlines())

        sq.send_to("Operator_Components Mgmnt", "Verify SLR(JWS)")
        endpoint = "/api/1.3/slr/verify"
        result = post("{}{}".format(self.operator_url, endpoint), json=req)
        debug_log.info("Sent SLR to Operator for verification, results:")
        debug_log.info("status code:{}\nreason: {}\ncontent: {}".format(result.status_code, result.reason, result.content))

        if result.ok:
            sq.task("Store following SLR into db")
            store = loads(result.text)
            slr_store = loads(result.text)["data"]["slr"]
            ssr_store = loads(result.text)["data"]["ssr"]
            debug_log.debug("Storing following SLR and SSR:")
            debug_log.debug(dumps(slr_store, indent=2))
            debug_log.debug(dumps(ssr_store, indent=2))
            payload = decode_payload(slr_store["attributes"]["payload"])
            if surrogate_id == payload["surrogate_id"]:
                self.helpers.store_slr_JSON(json=slr_store, slr_id=payload["link_id"], surrogate_id=payload["surrogate_id"])
                self.helpers.store_ssr_JSON(json=ssr_store)
                endpoint = "/api/1.3/slr/store_slr"
                debug_log.info("Posting SLR for storage in Service Mockup")
                result = post("{}{}".format(self.service_url, endpoint), json=store)  # Send copy to Service_Components
                # TODO: incase this fails we should try again.
            else:
                raise DetailedHTTPException(status=500,
                                            detail={
                                                "msg": "Surrogate id mismatch",
                                                "surrogate id's didn't match between requests.": loads(result.text)},
                                            title=result.reason)
        else:
            raise DetailedHTTPException(status=result.status_code,
                                        detail={"msg": "Something went wrong while verifying SLR with Operator_SLR.",
                                                "Error from Operator_SLR": loads(result.text)},
                                        title=result.reason)
        return store, 201

    @timeme
    @error_handler
    @api_logging
    def get(self):  # Fancy but only used for testing. Should be disabled/removed in production.
        sq.task("Debugging endpoint, fetch SLR's from db and return")
        jsons = {"jsons": {}}
        for storage_row in self.helpers.query_db("select * from storage;"):
            debug_log.info(storage_row["json"])
            jsons["jsons"][storage_row["surrogate_id"]] = loads(storage_row["json"])

        sq.reply_to("Operator_Components Mgmnt", "Return SLR's from db")
        return jsons

api.add_resource(GenerateSurrogateId, '/surrogate_id')
api.add_resource(StartServiceLinking, '/linking')
api.add_resource(StoreSLR, '/slr')
api.add_resource(StoreSSR, '/status')
