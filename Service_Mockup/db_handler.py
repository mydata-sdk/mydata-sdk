# -*- coding: utf-8 -*-
import sqlite3


def get_db(db_path):
    db = None
    if db is None:
        db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
        try:
            init_db(db)
        except Exception as e:
            pass
    return db


def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))


def sqlite_create_table(conn, table_name, table_columns):
    conn.cursor.execute("CREATE TABLE {} ({});".format(table_name, ",".join(table_columns)))
    conn.commit()

def init_db(conn):
    db = conn
    conn = db.cursor()
    # create db for codes
   # conn.execute('''CREATE TABLE codes  (ID TEXT PRIMARY KEY     NOT NULL,  code           TEXT    NOT NULL);''')
    conn.execute('''CREATE TABLE code_and_user_mapping
        (code TEXT PRIMARY KEY     NOT NULL,
         user_id           TEXT    NOT NULL);''')
    conn.execute('''CREATE TABLE surrogate_and_user_mapping
        (user_id TEXT PRIMARY KEY     NOT NULL,
         surrogate_id           TEXT    NOT NULL);''')
    conn.execute('''CREATE TABLE storage
        (ID TEXT PRIMARY KEY     NOT NULL,
         json           TEXT    NOT NULL);''')
    #sqlite_create_table(conn, "codes", ["id", "text", "code": "text"}) # Create table for codes
    #sqlite_create_table(conn, "")
    db.commit()
