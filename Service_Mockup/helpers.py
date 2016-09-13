# -*- coding: utf-8 -*-
import importlib
import logging
import pkgutil
from json import dumps
from sqlite3 import IntegrityError

from Crypto.PublicKey.RSA import importKey as import_rsa_key
from flask import Blueprint
from flask_restful import Api

import db_handler
from DetailedHTTPException import DetailedHTTPException

debug_log = logging.getLogger("debug")
class Helpers:
    def __init__(self, app_config):  # TODO: Reconsider only giving db_path
        self.db_path = app_config["DATABASE_PATH"]

    def query_db(self, query, args=(), one=False):
        """
        Query database
        :param query: 
        :param args: 
        :param one: 
        :return: None
        """
        db = db_handler.get_db(self.db_path)
        cur = db.cursor().execute(query, args)
        rv = cur.fetchall()
        db.close()
        return (rv[0] if rv else None) if one else rv

    def storeJSON(self, DictionaryToStore):
        db = db_handler.get_db(self.db_path)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)

        for key in DictionaryToStore:
            debug_log.info(key)
            # codes = {"jsons": {}}
            # codes = {"jsons": {}}
            try:
                cursor.execute("INSERT INTO storage (ID,json) \
                    VALUES (?, ?)", [key, dumps(DictionaryToStore[key])])
                db.commit()
            except IntegrityError as e:
                cursor.execute("UPDATE storage SET json=? WHERE ID=? ;", [dumps(DictionaryToStore[key]), key])
                db.commit()

    def storeCodeUser(self, DictionaryToStore):
        # {"code": "user_id"}
        db = db_handler.get_db(self.db_path)
        cursor = db.cursor()

        debug_log.info(DictionaryToStore)

        for key in DictionaryToStore:
            debug_log.info(key)
            cursor.execute("INSERT INTO code_and_user_mapping (code, user_id) \
                VALUES (?, ?)", [key, dumps(DictionaryToStore[key])])
            db.commit()

    def get_user_id_with_code(self, code):
        db = db_handler.get_db(self.db_path)
        for code_row in self.query_db("select * from code_and_user_mapping where code = ?;", [code]):
            user_from_db = code_row["user_id"]
            return user_from_db
        raise DetailedHTTPException(status=500,
                                    detail={"msg": "Unable to link code to user_id in database",
                                            "detail": {"code": code}},
                                    title="Failed to link code to user_id")
        # Letting world burn if user was not in db. Fail fast, fail hard.

    def storeSurrogateJSON(self, DictionaryToStore):
        db = db_handler.get_db(self.db_path)
        cursor = db.cursor()
        debug_log.info(DictionaryToStore)

        for key in DictionaryToStore:
            debug_log.info(key)
            cursor.execute("INSERT INTO surrogate_and_user_mapping (user_id, surrogate_id) \
                VALUES (?, ?)", [key, dumps(DictionaryToStore[key])])
            db.commit()
            
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
