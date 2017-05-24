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
from app.mod_database.helpers import get_db_cursor
from app.mod_database.models import EventLog
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


