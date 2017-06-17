# -*- coding: utf-8 -*-

"""
__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

# Import dependencies
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
from flask import current_app
from app.helpers import get_custom_logger
from app.mod_database.helpers import get_db_cursor

logger = get_custom_logger(__name__)


# For API Auth module
def get_account_id_by_username_and_password(username=None, password=None):
    username_to_check = str(username)
    logger.debug('username_to_check: ' + username_to_check)

    password_to_check = str(password)
    logger.debug('password_to_check: ' + password_to_check)

    try:
        ###
        # User info by username
        logger.debug('User info by username from DB')
        sql_query = "SELECT " \
                    "MyDataAccount.LocalIdentities.Accounts_id, " \
                    "MyDataAccount.LocalIdentities.id, " \
                    "MyDataAccount.LocalIdentities.username, " \
                    "MyDataAccount.LocalIdentityPWDs.password, " \
                    "MyDataAccount.Salts.salt  " \
                    "FROM MyDataAccount.LocalIdentities " \
                    "INNER JOIN MyDataAccount.LocalIdentityPWDs " \
                    "ON MyDataAccount.LocalIdentityPWDs.id = MyDataAccount.LocalIdentities.LocalIdentityPWDs_id " \
                    "INNER JOIN MyDataAccount.Salts " \
                    "ON MyDataAccount.Salts.LocalIdentities_id = MyDataAccount.LocalIdentities.id " \
                    "WHERE MyDataAccount.LocalIdentities.username = '%s'" % (username_to_check)

        if current_app.config["SUPER_DEBUG"]:
            logger.debug('sql_query: ' + repr(sql_query))

        # DB cursor
        cursor = get_db_cursor()

        cursor.execute(sql_query)

        data = cursor.fetchone()
        account_id_from_db = str(data[0])
        identity_id_from_db = str(data[1])
        username_from_db = str(data[2])
        password_from_db = str(data[3])
        salt_from_db = str(data[4])

    except Exception as exp:
        logger.debug('Authentication failed: ' + repr(exp))

        if current_app.config["SUPER_DEBUG"]:
            logger.debug('Exception: ' + repr(exp))

        return None

    else:
        logger.debug('User found with given username: ' + username)
        logger.debug('account_id_from_db: ' + account_id_from_db)
        logger.debug('identity_id_from_db: ' + identity_id_from_db)
        logger.debug('username_from_db: ' + username_from_db)
        logger.debug('password_from_db: ' + password_from_db)
        logger.debug('salt_from_db: ' + salt_from_db)

    logger.info("Checking password")
    if bcrypt.hashpw(password_to_check, salt_from_db) == password_from_db:
        logger.debug('Password hash from client: ' + bcrypt.hashpw(password_to_check, salt_from_db))
        logger.debug('Password hash from db    : ' + password_from_db)

        logger.debug('Authenticated')
        #cursor, user = get_account_by_id(cursor=cursor, account_id=int(account_id_from_db))
        user = {'account_id': account_id_from_db, 'username': username_from_db}
        logger.debug('User dict created')
        return user

    else:
        logger.debug('Password hash from client: ' + bcrypt.hashpw(password_to_check, salt_from_db))
        logger.debug('Password hash from db    : ' + password_from_db)

        logger.debug('Not Authenticated')
        return None

