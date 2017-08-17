# -*- coding: utf-8 -*-
import importlib
import logging
import pkgutil
import time
from json import dumps, loads
from base64 import urlsafe_b64decode as decode
from Crypto.PublicKey.RSA import importKey as import_rsa_key
from flask import Blueprint
from flask_restful import Api
import collections
import db_handler
from DetailedHTTPException import DetailedHTTPException

debug_log = logging.getLogger("debug")


class Helpers:
    def __init__(self, app_config):
        self.host = app_config["MYSQL_HOST"]
        self.cert_key_path = app_config["CERT_KEY_PATH"]
        self.keysize = app_config["KEYSIZE"]
        self.user = app_config["MYSQL_USER"]
        self.passwd = app_config["MYSQL_PASSWORD"]
        self.db = app_config["MYSQL_DB"]
        self.port = app_config["MYSQL_PORT"]
        self.operator_url = app_config["OPERATOR_URL"]

    def get_operator_url(self, operator_id):
        return self.operator_url

    def get_operator_access_url(self, operator_id):
        return "/api/1.3/dummyui/"

    def get_operator_login_url(self, operator_id):
        return self.get_operator_url(operator_id)+ self.get_operator_access_url(operator_id) + "linking_service"

    def query_db(self, query, args=()):
        """
        Simple queries to DB
        :param query: SQL query
        :param args: Arguments to inject into the query
        :return: Single hit for the given query
        """
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

    def store_code_user(self, DictionaryToStore):  # TODO: Replace with simpler function, no need for fancy for loops.
        # {"code": "user_id"}
        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)

        for key in DictionaryToStore:
            debug_log.info(key)
            cursor.execute("INSERT INTO code_and_user_mapping (code, user_id) \
                VALUES (%s, %s)", (key, dumps(DictionaryToStore[key])))
            db.commit()
        db.close()

    def get_user_id_with_code(self, code):
        try:
            query = self.query_db("select * from code_and_user_mapping where code=%s;", (code,))
            debug_log.info(query)
            user_from_db = loads(query)
            return user_from_db
        except Exception as e:
            debug_log.exception(e)
            raise DetailedHTTPException(status=500,
                                        detail={"msg": "Unable to link code to user_id in database",
                                                "detail": {"code": code}},
                                        title="Failed to link code to user_id")

        # Letting world burn if user was not in db. Fail fast, fail hard.

    def storeSurrogateJSON(self, user_id, surrogate_id, operator_id):

        db = db_handler.get_db(host=self.host, password=self.passwd, user=self.user, port=self.port, database=self.db)
        cursor = db.cursor()
        debug_log.info("Mapping surrogate_id '{}' with user_id '{}' for operator '{}'".format(surrogate_id,
                                                                                              user_id,
                                                                                              operator_id))

        try:
            cursor.execute("INSERT INTO surrogate_and_user_mapping (user_id, surrogate_id, operator_id) \
                VALUES (%s, %s, %s)", [user_id, surrogate_id, operator_id])
        except Exception as e:
            debug_log.exception(e)
            debug_log.debug("Storing surrogate_id into user/surrogate mapping FAILED,"
                            " likely surrogate_id assigned already.")
        db.commit()
        db.close()

            
def read_key(path, password=None):
    ##
    # Read RSA key from PEM file and return JWK object of it.
    ##
    try:
        from Service_Mockup.instance.settings import cert_password_path
        with open(cert_password_path, "r") as pw_file:
            password = pw_file.readline()
    except Exception as e:
        password = None
        pass
    if password is not None:  # Remove trailing line end if it exists
        password = password.strip("\n")

    from jwcrypto import jwk
    from jwkest.jwk import RSAKey
    with open(path, "r") as f:
        pem_data = f.read()
    try:
        rsajwk = RSAKey(key=import_rsa_key(pem_data, passphrase=password), use='sig')
    except ValueError as e:
        while True:
            pw = input("Please enter password for PEM file: ")
            try:
                rsajwk = RSAKey(key=import_rsa_key(pem_data, passphrase=pw), use='sig')
                save_pw = bool(str(input("Should the password be saved?(True/False): ")).capitalize())
                if save_pw:
                    with open("./cert_pw", "w+") as pw_file:
                        pw_file.write(pw)
                break

            except Exception as e:
                print(repr(e))
                print("Password may have been incorrect. Try again or terminate.")

    jwssa = jwk.JWK(**rsajwk.to_dict())
    return jwssa


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
