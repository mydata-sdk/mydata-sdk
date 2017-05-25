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
from app.helpers import get_custom_logger
from app.mod_database.helpers import get_db_cursor, execute_sql_count
from app.mod_database.models import EventLog, ServiceLinkRecord, ConsentRecord, Account, ServiceLinkStatusRecord, \
    ConsentStatusRecord
from app.app_modules import db

logger = get_custom_logger(__name__)


def create_event_log_entry(account_id=None, actor="", action="", resource="", timestamp=""):
    try:
        account_id = int(account_id)
    except Exception:
        raise TypeError("account_id MUST be int, not " + str(type(account_id)))
    try:
        actor = str(actor)
    except Exception:
        raise TypeError("actor MUST be str, not " + str(type(actor)))
    try:
        action = str(action)
    except Exception:
        raise TypeError("action MUST be str, not " + str(type(action)))
    try:
        resource = str(resource)
    except Exception:
        raise TypeError("resource MUST be str, not " + str(type(resource)))
    try:
        timestamp = str(timestamp)
    except Exception:
        raise TypeError("timestamp MUST be str, not " + str(type(timestamp)))

    # Constructing Event dict
    try:
        logger.debug("Constructing Event dict")

        event_dict = {
            'actor': actor,
            'action': action,
            'resource': resource,
            'timestamp': timestamp
        }

    except Exception as exp:
        logger.error('Could not construct Event dict: ' + repr(exp))
        return False

    # Get DB cursor
    try:
        logger.debug("Getting DB cursor")
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        return False

    # Create EventLog object
    try:
        logger.info("Creating EventLog object")
        log_entry = EventLog(account_id=account_id, event=event_dict)
    except Exception as exp:
        error_title = "Failed to create EventLog object"
        logger.error(error_title + ": " + repr(exp))
        return False
    else:
        logger.debug("EventLog object created: " + log_entry.log_entry)

    # Store EventLog object
    try:
        log_entry.to_db(cursor=cursor)
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to update EventLog to DB"
        logger.error(error_title + " --> rollback: " + repr(exp))
        db.connection.rollback()
        return False
    else:
        logger.info("EventLog stored")
        logger.info(log_entry.log_entry)
        return True


def get_db_statistics():
    # Get table names
    #
    db_entry_object = Account()
    account_table_name = db_entry_object.table_name
    #
    db_entry_object = ServiceLinkRecord()
    slr_table_name = db_entry_object.table_name
    #
    db_entry_object = ServiceLinkStatusRecord()
    ssr_table_name = db_entry_object.table_name
    #
    db_entry_object = ConsentRecord()
    cr_table_name = db_entry_object.table_name
    #
    db_entry_object = ConsentStatusRecord()
    csr_table_name = db_entry_object.table_name

    # Get DB cursor
    try:
        logger.debug("Getting DB cursor")
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        return False

    account_query = "SELECT COUNT(*) FROM " + account_table_name + ";"
    slr_query = "SELECT COUNT(*) FROM " + slr_table_name + ";"
    ssr_query = "SELECT COUNT(*) FROM " + ssr_table_name + ";"
    cr_query = "SELECT COUNT(*) FROM " + cr_table_name + ";"
    csr_query = "SELECT COUNT(*) FROM " + csr_table_name + ";"

    try:
        cursor, account_count = execute_sql_count(cursor=cursor, sql_query=account_query)
        cursor, slr_count = execute_sql_count(cursor=cursor, sql_query=slr_query)
        cursor, ssr_count = execute_sql_count(cursor=cursor, sql_query=ssr_query)
        cursor, cr_count = execute_sql_count(cursor=cursor, sql_query=cr_query)
        cursor, csr_count = execute_sql_count(cursor=cursor, sql_query=csr_query)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        count_dict = {
            'account': account_count,
            'service_link': slr_count,
            'service_link_status': ssr_count,
            'consent': cr_count,
            'consent_record': csr_count
        }
        return count_dict





