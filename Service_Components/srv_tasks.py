# -*- coding: utf-8 -*-
from requests import post
from factory import create_celery_app

celery = create_celery_app()

# TODO Possibly remove this on release
# @celery.task
# def CR_installer(crs_csrs_payload, sink_url, source_url):
#     # Get these as parameter or inside crs_csrs_payload
#     endpoint = "/api/1.2/cr/add_cr"
#     print(crs_csrs_payload)
#     source = post(source_url+endpoint, json=crs_csrs_payload["source"])
#     print(source.url, source.reason, source.status_code, source.text)
#
#     sink = post(sink_url+endpoint, json=crs_csrs_payload["sink"])
#     print(sink.url, sink.reason, sink.status_code, sink.text)


from sqlite3 import OperationalError, IntegrityError
import db_handler
from json import dumps, loads
from requests import get
from instance.settings import MYSQL_HOST, MYSQL_PASSWORD, MYSQL_USER, MYSQL_PORT, MYSQL_DB
@celery.task
def get_AuthToken(cr_id, operator_url, db_path):
    print(operator_url, db_path, cr_id)
    def storeToken(DictionaryToStore):
        db = db_handler.get_db(host=MYSQL_HOST, password=MYSQL_PASSWORD, user=MYSQL_USER, port=MYSQL_PORT, database=MYSQL_DB)
        cursor = db.cursor()
        for key in DictionaryToStore:
            try:
                cursor.execute("INSERT INTO token_storage (cr_id,token) \
                    VALUES (%s, %s)", (key, dumps(DictionaryToStore[key])))
                db.commit()
            except IntegrityError as e:  # Rewrite incase we get new token.
                cursor.execute("UPDATE token_storage SET token=? WHERE cr_id=%s ;", (dumps(DictionaryToStore[key]), key))
                db.commit()
        db.close()

    print(cr_id)
    token = get("{}/api/1.2/cr/auth_token/{}".format(operator_url, cr_id))  # TODO Get api path from some config?
    print(token.url, token.reason, token.status_code, token.text)
    store_dict = {cr_id: dumps(loads(token.text.encode()))}
    storeToken(store_dict)
