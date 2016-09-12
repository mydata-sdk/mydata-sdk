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
from app.mod_database.models import Particulars

logger = get_custom_logger(__name__)


def verify_api_key_match_with_account(account_id=None, api_key=None, endpoint=None):
    """
    Verifies that provided account id matches with account id fetched with api key.

    :param account_id:
    :param api_key:
    :param endpoint:
    :return:
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if api_key is None:
        raise AttributeError("Provide api_key as parameter")
    if endpoint is None:
        raise AttributeError("Provide endpoint as parameter")

    # Get Account ID by Api-Key
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

    # Check if Account IDs are matching
    logger.info("Check if Account IDs are matching")
    if str(account_id) is not str(account_id_by_api_key):
        error_title = "Authenticated Account ID not matching with Account ID that was provided with request"
        logger.error(error_title)
        raise ApiError(
            code=403,
            title=error_title,
            source=endpoint
        )
    else:
        logger.info("Account IDs are matching")
        logger.info("account_id: " + str(account_id))
        logger.info("account_id_by_api_key: " + str(account_id_by_api_key))

    return True


def get_particular(account_id=None, id=None, cursor=None):
    """
    Get one particular entry from database by Account ID and Particulars ID
    :param account_id:
    :param id:
    :return: Particular object
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
        account_particular = Particulars(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create Particulars object"
        logger.error(error_title + ": " + repr(exp))
        raise
    finally:
        logger.debug("Particulars object created: " + account_particular.log_entry)

    # Get particulars from DB
    try:
        cursor = account_particular.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Particulars from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("Particulars fetched")
        logger.info("Particulars fetched from db: " + account_particular.log_entry)

    return account_particular.to_api_dict


def get_particulars(account_id=None):
    """
    Get all Particulars -entries related to account
    :param account_id:
    :return:
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create particular_object")
    particular_object = Particulars()
    logger.info(particular_object.log_entry)
    logger.info("Get table name")
    table_name = particular_object.table_name
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
    particulars_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting particulars with particular_id: " + str(id))
        particular_dict = get_particular(account_id=account_id, id=id)
        particulars_list.append(particular_dict)
        logger.info("Particulars object added to list: " + json.dumps(particular_dict))

    return particulars_list


