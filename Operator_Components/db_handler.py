# -*- coding: utf-8 -*-
import logging

import MySQLdb

debug_log = logging.getLogger("debug")
def get_db(host, user, password, database, port):
    db = None
    if db is None:
        db = MySQLdb.connect(host=host, user=user, passwd=password, db=database, port=port)
        #db.row_factory = sqlite3.Row

        try:
            init_db(db)
        except Exception as e:
            debug_log.exception(e)
    return db


def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


def init_db(db):
    # create db for codes
    conn = db.cursor()
    conn.execute('''CREATE TABLE cr_tbl
        (rs_id TEXT PRIMARY KEY     NOT NULL,
         json           TEXT    NOT NULL);''')
    conn.execute('''CREATE TABLE rs_id_tbl
        (rs_id TEXT PRIMARY KEY     NOT NULL,
         used           BOOL    NOT NULL);''')
    conn.execute('''CREATE TABLE session_store
        (code TEXT PRIMARY KEY     NOT NULL,
         json           TEXT    NOT NULL);''')
    db.commit()
