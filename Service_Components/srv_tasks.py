# -*- coding: utf-8 -*-
from factory import create_celery_app

celery = create_celery_app()
from sqlite3 import OperationalError, IntegrityError
import db_handler
from json import dumps, loads
from requests import get
@celery.task
def get_AuthToken(cr_id, operator_url, db_path):
    print(operator_url, db_path, cr_id)
    def storeToken(DictionaryToStore):
        db = db_handler.get_db(db_path)
        try:
            db_handler.init_db(db)
        except OperationalError:
            pass
        for key in DictionaryToStore:
            try:
                db.execute("INSERT INTO token_storage (cr_id,token) \
                    VALUES (?, ?)", [key, dumps(DictionaryToStore[key])])
                db.commit()
            except IntegrityError as e:  # Rewrite incase we get new token.
                db.execute("UPDATE token_storage SET token=? WHERE cr_id=? ;", [dumps(DictionaryToStore[key]), key])
                db.commit()

    print(cr_id)
    token = get("{}/api/1.2/cr/auth_token/{}".format(operator_url, cr_id))  # TODO Get api path from some config?
    print(token.url, token.reason, token.status_code, token.text)
    store_dict = {cr_id: dumps(loads(token.text.encode()))}
    storeToken(store_dict)

