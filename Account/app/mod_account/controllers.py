# -*- coding: utf-8 -*-

# Import dependencies
import json
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom
from random import randint

# Import flask dependencies
from flask import Blueprint, render_template, make_response, flash, session
from flask.ext.login import login_user, login_required
from flask_restful import Resource, Api, reqparse

# Import the database object from the main app module
from app import db, api, login_manager, app

# Import services
from app.helpers import get_custom_logger, ApiError
from app.mod_api_auth.controllers import get_account_id_by_api_key
from app.mod_database.helpers import get_db_cursor, get_primary_keys_by_account_id

# create logger with 'spam_application'
from app.mod_database.models import Particulars, Contacts

logger = get_custom_logger(__name__)


def verify_account_id_match(account_id=None, api_key=None, account_id_to_compare=None, endpoint=None):
    """
    Verifies that provided account id matches with account id fetched with api key.

    :param account_id:
    :param api_key:
    :param endpoint:
    :return:
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if endpoint is None:
        raise AttributeError("Provide endpoint as parameter")

    # Get Account ID by Api-Key or compare to provided
    if api_key is not None:
        try:
            logger.info("Fetching Account ID by Api-Key")
            account_id_by_api_key = get_account_id_by_api_key(api_key=api_key)
        except Exception as exp:
            error_title = "Account ID not found with provided ApiKey"
            logger.error(error_title)
            raise ApiError(
                code=403,
                title=error_title,
                detail=repr(exp),
                source=endpoint
            )
        else:
            logger.info("account_id_by_api_key: " + str(account_id_by_api_key))
            account_id_to_compare = account_id_by_api_key
            error_title = "Authenticated Account ID not matching with Account ID that was provided with request"
    elif account_id_to_compare is not None:
        logger.info("account_id_to_compare provided as parameter")
        error_title = "Account ID in payload not matching with Account ID that was provided with request"

    # Check if Account IDs are matching
    logger.info("Check if Account IDs are matching")
    logger.info("account_id: " + str(account_id))
    logger.info("account_id_to_compare: " + str(account_id_to_compare))
    if str(account_id) != str(account_id_to_compare):
        logger.error(error_title)
        raise ApiError(
            code=403,
            title=error_title,
            source=endpoint
        )
    else:
        logger.info("Account IDs are matching")
        logger.info("account_id: " + str(account_id))
        logger.info("account_id_to_compare: " + str(account_id_to_compare))

    return True


#
# Particulars
def get_particular(account_id=None, id=None, cursor=None):
    """
    Get one particular entry from database by Account ID and Particulars ID
    :param account_id:
    :param id:
    :return: Particular dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Particulars(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create Particulars object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("Particulars object created: " + db_entry_object.log_entry)

    # Get particulars from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Particulars from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("Particulars fetched")
        logger.info("Particulars fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_particulars(account_id=None):
    """
    Get all Particulars -entries related to account
    :param account_id:
    :return: List of Particular dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create db_entry_object")
    db_entry_object = Particulars()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for particulars
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get Particulars from database
    logger.info("Get Particulars from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting particulars with particular_id: " + str(id))
        db_entry_dict = get_particular(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("Particulars object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def update_particular(account_id=None, id=None, attributes=None, cursor=None):
    """
    Update one particular entry at database identified by Account ID and Particulars ID
    :param account_id:
    :param id:
    :return: Particular dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Particulars(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create Particulars object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("Particulars object created: " + db_entry_object.log_entry)

    # Get particulars from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Particulars from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("Particulars fetched")
        logger.info("Particulars fetched from db: " + db_entry_object.log_entry)

    # Update Particulars object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to update.")
        return db_entry_object.to_api_dict
    else:
        logger.info("Particulars object to update: " + db_entry_object.log_entry)

    # log provided attributes
    for key, value in attributes.items():
        logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Update object attributes
    if "lastname" in attributes:
        logger.info("Updating lastname")
        old_value = str(db_entry_object.lastname)
        new_value = str(attributes.get("lastname", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.lastname = new_value
        logger.info(db_entry_object.log_entry)

    if "firstname" in attributes:
        logger.info("Updating firstname")
        old_value = str(db_entry_object.firstname)
        new_value = str(attributes.get("firstname", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.firstname = new_value
        logger.info(db_entry_object.log_entry)

    if "img_url" in attributes:
        logger.info("Updating img_url")
        old_value = str(db_entry_object.img_url)
        new_value = str(attributes.get("img_url", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.img_url = new_value
        logger.info(db_entry_object.log_entry)

    if "date_of_birth" in attributes:
        logger.info("Updating date_of_birth")
        old_value = str(db_entry_object.date_of_birth)
        new_value = str(attributes.get("date_of_birth", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.date_of_birth = new_value
        logger.info(db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.update_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to update Particulars to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("Particulars updated")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict


#
# Contacts
def get_contact(account_id=None, id=None, cursor=None):
    """
    Get one contact entry from database by Account ID and contact ID
    :param account_id:
    :param id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Contacts(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create contact object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("contact object created: " + db_entry_object.log_entry)

    # Get contact from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch contact from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("contact fetched")
        logger.info("contact fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_contacts(account_id=None):
    """
    Get all contact -entries related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create contact")
    db_entry_object = Contacts()
    logger.info(db_entry_object.log_entry)
    logger.info("Get table name")
    table_name = db_entry_object.table_name
    logger.info("Got table name: " + str(table_name))

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Get primary keys for particulars
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get contacts from database
    logger.info("Get contacts from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting contacts with particular_id: " + str(id))
        db_entry_dict = get_contact(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("contact object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def add_contact(account_id=None, attributes=None, cursor=None):
    """
    Add one contacts entry at database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: Particular dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    # Update contacts object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to add.")
        raise StandardError("Not adding empty entry to database")
    else:
        # log provided attributes
        for key, value in attributes.items():
            logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Create object
    try:
        db_entry_object = Contacts(
            account_id=account_id,
            address1=str(attributes.get("address1", "")),
            address2=str(attributes.get("address2", "")),
            postal_code=str(attributes.get("postalCode", "")),
            city=str(attributes.get("city", "")),
            state=str(attributes.get("state", "")),
            country=str(attributes.get("country", "")),
            type=str(attributes.get("type", "")),
            prime=str(attributes.get("primary", ""))
        )
    except Exception as exp:
        error_title = "Failed to create contacts object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("contacts object created: " + db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.to_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to add contacts to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("contacts added")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def update_contact(account_id=None, id=None, attributes=None, cursor=None):
    """
    Update one contacts entry at database identified by Account ID and ID
    :param account_id:
    :param id:
    :return: Particular dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if id is None:
        raise AttributeError("Provide id as parameter")
    if attributes is None:
        raise AttributeError("Provide attributes as parameter")
    if not isinstance(attributes, dict):
        raise AttributeError("attributes must be a dict")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = Contacts(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create contacts object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("contacts object created: " + db_entry_object.log_entry)

    # Get contacts from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch contacts from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("contacts fetched")
        logger.info("contacts fetched from db: " + db_entry_object.log_entry)

    # Update contacts object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to update.")
        return db_entry_object.to_api_dict
    else:
        logger.info("contacts object to update: " + db_entry_object.log_entry)

    # log provided attributes
    for key, value in attributes.items():
        logger.debug("attributes[" + str(key) + "]: " + str(value))

    # Update object attributes
    if "address1" in attributes:
        logger.info("Updating address1")
        old_value = str(db_entry_object.address1)
        new_value = str(attributes.get("address1", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.address1 = new_value
        logger.info(db_entry_object.log_entry)

    if "address2" in attributes:
        logger.info("Updating address2")
        old_value = str(db_entry_object.address2)
        new_value = str(attributes.get("address2", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.address2 = new_value
        logger.info(db_entry_object.log_entry)

    if "postalCode" in attributes:
        logger.info("Updating postalCode")
        old_value = str(db_entry_object.postal_code)
        new_value = str(attributes.get("postalCode", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.postal_code = new_value
        logger.info(db_entry_object.log_entry)

    if "city" in attributes:
        logger.info("Updating city")
        old_value = str(db_entry_object.city)
        new_value = str(attributes.get("city", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.city = new_value
        logger.info(db_entry_object.log_entry)

    if "state" in attributes:
        logger.info("Updating state")
        old_value = str(db_entry_object.state)
        new_value = str(attributes.get("state", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.state = new_value
        logger.info(db_entry_object.log_entry)

    if "country" in attributes:
        logger.info("Updating country")
        old_value = str(db_entry_object.country)
        new_value = str(attributes.get("country", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.country = new_value
        logger.info(db_entry_object.log_entry)

    if "type" in attributes:
        logger.info("Updating type")
        old_value = str(db_entry_object.type)
        new_value = str(attributes.get("type", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.type = new_value
        logger.info(db_entry_object.log_entry)

    if "primary" in attributes:
        logger.info("Updating primary")
        old_value = str(db_entry_object.prime)
        new_value = str(attributes.get("primary", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.prime = new_value
        logger.info(db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.update_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to update contacts to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("contacts updated")
        logger.info(db_entry_object.log_entry)

    return db_entry_object.to_api_dict

