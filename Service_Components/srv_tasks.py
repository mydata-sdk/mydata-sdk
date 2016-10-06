# -*- coding: utf-8 -*-
from requests import post
from factory import create_celery_app
import urllib
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
    def storeToken(DictionaryToStore):  # TODO: Figure if this could be put to helpers without getting to trouble with settings
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


    req = get("http://service_components:7000/api/1.2/sink_flow/init")
    print(req.url, req.status_code, req.content)

    data  = {"cr_id": "4b50b597-a981-4f9a-8f1b-86fecc96d479",
             "user_id": "cfc2157d-59b3-4e6a-98ee-d49b946345f6_f9be871c-cb0d-44b8-8cab-ef2ff9fdc7f0",
             "rs_id": urllib.quote_plus("http://service_components:7000||9af5bcc3-d49d-44a5-a486-e0bc137523cf")}

    req = post("http://service_components:7000/api/1.2/sink_flow/dc", json=data)
    # req = get("http://service_components:7000/api/1.2/sink_flow/"
    #           "user/"+"95479a08-80cc-4359-ba28-b8ca23ff5572_53af88dc-33de-44be-bc30-e0826db9bd6c"+"/"
    #           "consentRecord/"+"cd431509-777a-4285-8211-95c5ac577537"+"/"
    #           "resourceSet/"+urllib.quote_plus("http://service_components:7000||9aebb487-0c83-4139-b12c-d7fcea93a3ad"))
    print(req.url, req.status_code, req.content)
