# -*- coding: utf-8 -*-

# Import dependencies
import json
import uuid
import logging
from _mysql import IntegrityError

import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom
from random import randint
from time import time

# Import flask dependencies
from flask import Blueprint, render_template, make_response, flash, session, current_app
from flask_login import login_user, login_required
from flask_restful import Resource, Api, reqparse

# Import the database object
from app.app_modules import db

# Import services
from app.helpers import get_custom_logger, ApiError, get_utc_time
from app.mod_blackbox.controllers import get_account_public_key, generate_and_sign_jws
from app.mod_database.helpers import get_db_cursor, get_slr_ids

# create logger with 'spam_application'
from app.mod_database.models import SurrogateId, ServiceLinkRecord

logger = get_custom_logger(__name__)


def init_slr_source(account_id=None, slr_id=None, endpoint="init_slr_sink()"):

    logger.info("init_slr_sink()")

    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")

    if not isinstance(account_id, str):
        try:
            account_id = str(account_id)
        except Exception:
            raise TypeError("account_id MUST be str, not " + str(type(account_id)))
    if not isinstance(slr_id, str):
        try:
            slr_id = str(slr_id)
        except Exception:
            raise TypeError("slr_id MUST be str, not " + str(type(slr_id)))
    if not isinstance(endpoint, str):
        try:
            endpoint = str(endpoint)
        except Exception:
            raise TypeError("endpoint MUST be str, not " + str(type(endpoint)))

    logger.info("Initing SLR")
    try:
        slr_entry = ServiceLinkRecord(
            service_link_record_id=slr_id,
            account_id=account_id
        )
    except Exception as exp:
        logger.error('Could not create Service Link Record object: ' + repr(exp))
        raise ApiError(code=500, title="Failed to create Service Link Record object", detail=repr(exp), source=endpoint)
    else:
        logger.info("Service Link Record entry created")
        logger.debug(slr_entry.log_entry)

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # Store DB entry
    try:
        cursor = slr_entry.to_db(cursor=cursor)
        slr_id = slr_entry.service_link_record_id
        db.connection.commit()
    except IntegrityError as exp:
        error_title = "Service Link ID already exists"
        error_detail = str(exp.args[1])
        logger.error(error_title + " - " + error_detail)
        db.connection.rollback()
        logger.debug('--> rollback')
        raise ApiError(code=409, title=error_title, detail=error_detail, source=endpoint)
    except Exception as exp:
        logger.error('Slr init commit failed: ' + repr(exp))
        db.connection.rollback()
        logger.debug('--> rollback')
        raise ApiError(code=500, title="Failed to store init SLR", detail=repr(exp), source=endpoint)
    else:
        logger.info('Slr initialized commited')
        logger.debug("slr_entry: " + slr_entry.log_entry)
        return slr_id


def init_slr_sink(account_id=None, slr_id=None, pop_key=None, endpoint="init_slr_sink()"):

    logger.info("init_slr_sink()")

    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if pop_key is None:
        raise AttributeError("Provide pop_key as parameter")

    if not isinstance(account_id, str):
        try:
            account_id = str(account_id)
        except Exception:
            raise TypeError("account_id MUST be str, not " + str(type(account_id)))
    if not isinstance(slr_id, str):
        try:
            slr_id = str(slr_id)
        except Exception:
            raise TypeError("slr_id MUST be str, not " + str(type(slr_id)))
    if not isinstance(pop_key, dict):
        try:
            pop_key = dict(pop_key)
        except Exception:
            raise TypeError("pop_key MUST be dict, not " + str(type(pop_key)))
    if not isinstance(endpoint, str):
        try:
            endpoint = str(endpoint)
        except Exception:
            raise TypeError("endpoint MUST be str, not " + str(type(endpoint)))

    logger.info("Initing SLR")
    try:
        slr_entry = ServiceLinkRecord(
            service_link_record_id=slr_id,
            account_id=account_id,
            pop_key=pop_key
        )
    except Exception as exp:
        logger.error('Could not create Service Link Record object: ' + repr(exp))
        raise ApiError(code=500, title="Failed to create Service Link Record object", detail=repr(exp), source=endpoint)
    else:
        logger.info("Service Link Record entry created")
        logger.debug(slr_entry.log_entry)

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # Store DB entry
    try:
        cursor = slr_entry.to_db(cursor=cursor)
        slr_id = slr_entry.service_link_record_id
        db.connection.commit()
    except IntegrityError as exp:
        error_title = "Service Link ID already exists"
        error_detail = str(exp.args[1])
        logger.error(error_title + " - " + error_detail)
        db.connection.rollback()
        logger.debug('--> rollback')
        raise ApiError(code=409, title=error_title, detail=error_detail, source=endpoint)
    except Exception as exp:
        logger.error('Slr init commit failed: ' + repr(exp))
        db.connection.rollback()
        logger.debug('--> rollback')
        raise ApiError(code=500, title="Failed to store init SLR", detail=repr(exp), source=endpoint)
    else:
        logger.info('Slr initialized commited')
        logger.debug("slr_entry: " + slr_entry.log_entry)
        return slr_id


def get_slr_record(account_id=None, slr_id=None, endpoint="get_slr_record()"):

    logger.info("get_slr_record()")

    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")

    if not isinstance(account_id, str):
        try:
            account_id = str(account_id)
        except Exception:
            raise TypeError("account_id MUST be str, not " + str(type(account_id)))
    if not isinstance(slr_id, str):
        try:
            slr_id = str(slr_id)
        except Exception:
            raise TypeError("slr_id MUST be str, not " + str(type(slr_id)))
    if not isinstance(endpoint, str):
        try:
            endpoint = str(endpoint)
        except Exception:
            raise TypeError("endpoint MUST be str, not " + str(type(endpoint)))

    logger.info("Creating ServiceLinkRecord object")
    try:
        slr_entry = ServiceLinkRecord(
            service_link_record_id=slr_id,
            account_id=account_id
        )
    except Exception as exp:
        logger.error('Could not create Service Link Record object: ' + repr(exp))
        raise ApiError(code=500, title="Failed to create Service Link Record object", detail=repr(exp), source=endpoint)
    else:
        logger.info("Service Link Record entry created")
        logger.debug(slr_entry.log_entry)

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    logger.info("Get ServiceLinkRecord from database")
    try:
        cursor = slr_entry.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Could not get ServiceLinkRecord from database"
        error_detail = str(exp.message)
        logger.error(error_title + " - " + error_detail)
        raise
    else:
        logger.info('Got ServiceLinkRecord from database')
        logger.debug("slr_entry: " + slr_entry.log_entry)
        return slr_entry


def sign_slr(account_id=None, slr_payload=None, endpoint="sign_slr(account_id, slr_payload, endpoint)"):
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_payload is None:
        raise AttributeError("Provide slr_payload as parameter")

    logger.info("Signing Service Link Record")

    # Get Account owner's public key
    try:
        account_public_key, account_kid = get_account_public_key(account_id=account_id)
        account_public_key_log_entry = account_public_key
        account_public_key = json.loads(account_public_key)
    except Exception as exp:
        logger.error("Could not get account owner's public key: " + repr(exp))
        raise ApiError(code=500, title="Failed to get account owner's public key", detail=repr(exp), source=endpoint)
    else:
        logger.info("Account owner's public key and kid fetched")
        logger.debug("account_public_key: " + account_public_key_log_entry)

    # Fill Account key to cr_keys
    try:
        keys = []
        keys.append(account_public_key)
        slr_payload['cr_keys'] = keys
    except Exception as exp:
        logger.error("Could not fill account owner's public key to cr_keys: " + repr(exp))
        raise ApiError(code=500, title="Failed to fill account owner's public key to cr_keys", detail=repr(exp), source=endpoint)
    else:
        logger.info("Account owner's public key added to cr_keys")

    # Sign slr
    slr_signed = {}
    try:
        slr_signed_json = generate_and_sign_jws(account_id=account_id, jws_payload=json.dumps(slr_payload))
    except Exception as exp:
        logger.error('Could not create Service Link Record: ' + repr(exp))
        raise ApiError(code=500, title="Failed to create Service Link Record", detail=repr(exp), source=endpoint)
    else:
        logger.info('Service Link Record created and signed')
        logger.debug("slr_payload: " + json.dumps(slr_payload))
        logger.debug("slr_signed_json: " + slr_signed_json)
        try:
            logger.info("Converting signed CSR from json to dict")
            slr_signed_dict = json.loads(slr_signed_json)
        except Exception as exp:
            logger.error('Could not convert signed SLR from json to dict: ' + repr(exp))
            raise ApiError(code=500, title="Failed to convert signed SLR from json to dict", detail=repr(exp), source=endpoint)
        else:
            logger.info('Converted signed SLR from json to dict')
            logger.debug('slr_signed_dict: ' + json.dumps(slr_signed_dict))

        return slr_signed_dict


def sign_ssr(account_id=None, ssr_payload=None, endpoint="sign_ssr(account_id, slr_payload, endpoint)"):
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if ssr_payload is None:
        raise AttributeError("Provide ssr_payload as parameter")

    logger.info("Signing Service Link Status Record")

    # Sign ssr
    ssr_signed = {}
    try:
        ssr_signed_json = generate_and_sign_jws(account_id=account_id, jws_payload=json.dumps(ssr_payload))
    except Exception as exp:
        logger.error('Could not create Service Link Status Record: ' + repr(exp))
        raise ApiError(code=500, title="Failed to create Service Link Record", detail=repr(exp), source=endpoint)
    else:
        logger.info('Service Link Status Record created and signed')
        logger.debug("ssr_payload: " + json.dumps(ssr_payload))
        logger.debug("ssr_signed_json: " + ssr_signed_json)
        try:
            logger.info("Converting signed CSR from json to dict")
            ssr_signed_dict = json.loads(ssr_signed_json)
        except Exception as exp:
            logger.error('Could not convert signed SLR from json to dict: ' + repr(exp))
            raise ApiError(code=500, title="Failed to convert signed SLR from json to dict", detail=repr(exp), source=endpoint)
        else:
            logger.info('Converted signed SLR from json to dict')
            logger.debug('ssr_signed_dict: ' + json.dumps(ssr_signed_dict))

        return ssr_signed_dict


def store_slr_and_ssr(slr_entry=None, ssr_entry=None, endpoint="sign_ssr(account_id, slr_payload, endpoint)"):
    if slr_entry is None:
        raise AttributeError("Provide slr_entry as parameter")
    if ssr_entry is None:
        raise AttributeError("Provide ssr_entry as parameter")

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    try:
        # SLR update
        cursor = slr_entry.update_db(cursor=cursor)

        # SLR primary key to SSR
        ssr_entry.service_link_records_id = slr_entry.id

        # SSR Insert
        cursor = ssr_entry.to_db(cursor=cursor)

        db.connection.commit()
    except Exception as exp:
        logger.error('Slr and Ssr commit failed: ' + repr(exp))
        db.connection.rollback()
        logger.error('--> rollback')
        logger.error("slr_entry: " + slr_entry.log_entry)
        logger.error("ssr_entry: " + ssr_entry.log_entry)
        raise ApiError(code=500, title="Failed to store slr and ssr", detail=repr(exp), source=endpoint)
    else:
        logger.debug('Slr and Ssr commited')
        logger.debug("slr_entry: " + slr_entry.log_entry)
        logger.debug("ssr_entry: " + ssr_entry.log_entry)
        return slr_entry, ssr_entry


def get_surrogate_id_by_account_and_service(account_id=None, service_id=None, endpoint="(get_surrogate_id_by_account_and_Service)"):
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if service_id is None:
        raise AttributeError("Provide service_id as parameter")

    # Create Surrogate id object
    try:
        sur_id_obj = SurrogateId(service_id=service_id, account_id=account_id)
    except Exception as exp:
        logger.error('Could not create SurrogateId object: ' + repr(exp))
        raise
    else:
        logger.info("SurrogateId object created")
        logger.debug("sur_id_obj: " + sur_id_obj.log_entry)

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    try:
        cursor = sur_id_obj.from_db(cursor=cursor)
    except Exception as exp:
        logger.error('Could not get surrogate id from db: ' + repr(exp))
        raise
    else:
        logger.debug("Got sur_id_obj:" + json.dumps(sur_id_obj.to_dict))
        logger.debug("sur_id_obj: " + sur_id_obj.log_entry)
        return sur_id_obj.to_dict


##################################
###################################
# Service Link Records
##################################
##################################
def get_slr(account_id=None, slr_id=None, cursor=None):
    """
    Get one slr entry from database by Account ID and ID
    :param account_id:
    :param slr_id:
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
        db_entry_object = ServiceLinkRecord(account_id=account_id, service_link_record_id=slr_id)
    except Exception as exp:
        error_title = "Failed to create slr object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("slr object created: " + db_entry_object.log_entry)

    # Get slr from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch slr from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("slr fetched")
        logger.info("slr fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_slrs(account_id=None):
    """
    Get all slr -entries related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create slr")
    db_entry_object = ServiceLinkRecord()
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

    # Get primary keys for slr
    try:
        cursor, id_list = get_slr_ids(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get slrs from database
    logger.info("Get slrs from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting slr with slr_id: " + str(id))
        db_entry_dict = get_slr(account_id=account_id, slr_id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("slr object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list
