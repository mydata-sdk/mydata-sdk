# -*- coding: utf-8 -*-

# Import dependencies
import json
import uuid
import logging
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0
#from Crypto.Hash import SHA512
#from Crypto.Random.random import StrongRandom
from random import randint
from time import time

# Import flask dependencies
from flask import Blueprint, render_template, make_response, flash, session
from flask.ext.login import login_user, login_required
from flask_restful import Resource, Api, reqparse

# Import the database object from the main app module
from app import db, api, login_manager, app

# Import services
from app.helpers import get_custom_logger, ApiError, get_utc_time
from app.mod_blackbox.controllers import get_account_public_key, generate_and_sign_jws
from app.mod_database.helpers import get_db_cursor, get_last_csr_id

# create logger with 'spam_application'
from app.mod_database.models import SurrogateId, ConsentRecord, ServiceLinkRecord, ConsentStatusRecord

logger = get_custom_logger(__name__)


def sign_cr(account_id=None, payload=None, endpoint="sign_slr(account_id, payload, endpoint)"):
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if payload is None:
        raise AttributeError("Provide payload as parameter")

    logger.info("Signing Consent Record")

    # Get Account owner's public key
    try:
        account_public_key, account_kid = get_account_public_key(account_id=account_id)
        account_public_key = json.loads(account_public_key)
    except Exception as exp:
        logger.error("Could not get account owner's public key: " + repr(exp))
        raise ApiError(code=500, title="Failed to get account owner's public key", detail=repr(exp), source=endpoint)
    else:
        logger.info("Account owner's public key and kid fetched")

    # Sign cr
    try:
        cr_signed = generate_and_sign_jws(account_id=account_id, jws_payload=json.dumps(payload))
    except Exception as exp:
        logger.error('Could not create Consent Record: ' + repr(exp))
        raise ApiError(code=500, title="Failed to create Consent Record", detail=repr(exp), source=endpoint)
    else:
        logger.info('Service Link Record created and signed')
        logger.debug('cr_signed: ' + cr_signed)
        return cr_signed


def sign_csr(account_id=None, payload=None, endpoint="sign_csr(account_id, payload, endpoint)"):
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if payload is None:
        raise AttributeError("Provide ssr_payload as parameter")

    logger.info("Signing Service Link Status Record")

    # Sign csr
    try:
        csr_signed = generate_and_sign_jws(account_id=account_id, jws_payload=json.dumps(payload))
    except Exception as exp:
        logger.error('Could not create Consent Status Record: ' + repr(exp))
        raise ApiError(code=500, title="Failed to create Consent Status Record", detail=repr(exp), source=endpoint)
    else:
        logger.info('SConsent Status Record created and signed')
        logger.debug('csr_signed: ' + csr_signed)
        return csr_signed


def store_cr_and_csr(source_slr_entry=None, sink_slr_entry=None, source_cr_entry=None, source_csr_entry=None, sink_cr_entry=None, sink_csr_entry=None, endpoint="store_cr_and_csr()"):
    if source_slr_entry is None:
        raise AttributeError("Provide source_slr_entry as parameter")
    if sink_slr_entry is None:
        raise AttributeError("Provide sink_slr_entry as parameter")
    if source_cr_entry is None:
        raise AttributeError("Provide source_cr_entry as parameter")
    if source_csr_entry is None:
        raise AttributeError("Provide source_csr_entry as parameter")
    if sink_cr_entry is None:
        raise AttributeError("Provide sink_cr_entry as parameter")
    if sink_csr_entry is None:
        raise AttributeError("Provide sink_csr_entry as parameter")

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    try:
        # Get Source's SLR from DB
        try:
            cursor = source_slr_entry.from_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to fetch Source's SLR from DB"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("source_slr_entry: " + source_slr_entry.log_entry)

        # Get Sink's SLR from DB
        try:
            cursor = sink_slr_entry.from_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to fetch Sink's SLR from DB"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("sink_slr_entry: " + sink_slr_entry.log_entry)

        # Get Source's SLR ID
        try:
            source_cr_entry.service_link_records_id = source_slr_entry.id
        except Exception as exp:
            error_title = "Failed to fetch Source's Service Link Record ID"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("source_cr_entry: " + source_cr_entry.log_entry)

        # Get Sink's SLR ID
        try:
            sink_cr_entry.service_link_records_id = sink_slr_entry.id
        except Exception as exp:
            error_title = "Failed to fetch Sink's Service Link Record ID"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("sink_cr_entry: " + sink_cr_entry.log_entry)

        # Store Source CR
        try:
            cursor = source_cr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Source's Consent Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("source_cr_entry: " + source_cr_entry.log_entry)

        # Link Source's CSR with it's CR
        try:
            source_csr_entry.consent_records_id = source_cr_entry.id
        except Exception as exp:
            error_title = "Failed to link Source's CSR with it's CR"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug(source_csr_entry.log_entry)

        # Store Source CSR
        try:
            cursor = source_csr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Source's Consent Status Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("source_csr_entry: " + source_csr_entry.log_entry)

        # Store Sink CR
        try:
            cursor = sink_cr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Sink's Consent Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("sink_cr_entry: " + sink_cr_entry.log_entry)

        # Link Sink's CSR with it's CR
        try:
            sink_csr_entry.consent_records_id = sink_cr_entry.id
        except Exception as exp:
            error_title = "Failed to link Sink's CSR with it's CR"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("sink_csr_entry: " + sink_csr_entry.log_entry)

        # Store Sink CSR
        try:
            cursor = sink_csr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Sink's Consent Status Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        finally:
            logger.debug("sink_csr_entry: " + sink_csr_entry.log_entry)

        # Commit
        db.connection.commit()
    except Exception as exp:
        logger.debug('commit failed: ' + repr(exp))
        db.connection.rollback()
        logger.debug('--> rollback')
        #raise ApiError(code=500, title="Failed to store CR's and CSR's", detail=repr(exp), source=endpoint)
        raise
    else:
        logger.info("CR's and CSR's commited")

        try:
            # TODO: Change to_dict -> to_record_dict_external
            data = {
                'source': {
                    'CR': source_cr_entry.to_dict,
                    'CSR': source_csr_entry.to_dict
                },
                'sink': {
                    'CR': sink_cr_entry.to_dict,
                    'CSR': sink_csr_entry.to_dict
                }
            }
        except Exception as exp:
            logger.error("Could not construct data object: "+ repr(exp))
            data = {}
        else:
            return data


def get_auth_token_data(sink_cr_object=None, endpoint="get_auth_token_data()"):
    if sink_cr_object is None:
        raise AttributeError("Provide sink_cr_object as parameter")

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # Get Sink's CR from DB
    try:
        cursor = sink_cr_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Sink's CR from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_cr_object: " + sink_cr_object.log_entry)

    # Get required id's from Sink's CR
    try:
        sink_rs_id = str(sink_cr_object.resource_set_id)
        sink_slr_primary_key = str(sink_cr_object.service_link_records_id)
    except Exception as exp:
        error_title = "Failed to get id's from Sink's CR"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_rs_id: " + sink_rs_id)

    # Init Source's Consent Record Object
    try:
        source_cr_entry = ConsentRecord(resource_set_id=sink_rs_id, role="Source")
    except Exception as exp:
        error_title = "Failed to create Source's Consent Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("source_cr_entry: " + source_cr_entry.log_entry)

    # Get Source's Consent Record from DB
    try:
        cursor = source_cr_entry.from_db(cursor=cursor)
        source_cr = source_cr_entry.to_record_dict
    except Exception as exp:
        error_title = "Failed to fetch Source's CR from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("source_cr_entry: " + source_cr_entry.log_entry)
        logger.debug("source_cr: " + json.dumps(source_cr))

    # Init Sink's Service Link Record Object
    try:
        sink_slr_entry = ServiceLinkRecord(id=sink_slr_primary_key)
    except Exception as exp:
        error_title = "Failed to create Source's Service Link Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("source_cr_entry: " + source_cr_entry.log_entry)

    # Get Source's Consent Record from DB
    try:
        cursor = sink_slr_entry.from_db(cursor=cursor)
        sink_slr = sink_slr_entry.to_record_dict
    except Exception as exp:
        error_title = "Failed to fetch Sink's SLR from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_slr_entry: " + sink_slr_entry.log_entry)
        logger.debug("sink_slr: " + json.dumps(sink_slr))

    return source_cr, sink_slr


def get_last_cr_status(cr_id=None, endpoint="get_last_cr_status()"):
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # Init Consent Record Object
    try:
        logger.info("Create ConsentRecord object")
        cr_entry = ConsentRecord(consent_id=cr_id)
        logger.info(cr_entry.log_entry)
    except Exception as exp:
        error_title = "Failed to create Consent Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_cr_entry: " + cr_entry.log_entry)

    # Get Consent Record from DB
    try:
        cursor = cr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Consent Record not found from DB with given ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to fetch Consent Record from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("cr_entry: " + cr_entry.log_entry)

    # Get Consent Record ID of cr_entry
    try:
        cr_entry_id = cr_entry.consent_id
    except Exception as exp:
        error_title = "Failed to get Consent Record ID from object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("cr_entry_id: " + str(cr_entry_id))

    # Create Consent Status Record object
    try:
        csr_entry = ConsentStatusRecord()
    except Exception as exp:
        error_title = "Failed to create Consent Status Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("csr_entry: " + csr_entry.log_entry)

    # Get database table name for Consent Status Record
    try:
        logger.info("Get Consent Status Record table name")
        csr_table_name = csr_entry.table_name
    except Exception as exp:
        error_title = "Failed to get Consent Status Record table name"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Got Consent Status Record table name: " + str(csr_table_name))

    # Get Consent Status Record ID
    try:
        cursor, csr_id = get_last_csr_id(cursor=cursor, cr_id=cr_id, table_name=csr_table_name)
    except IndexError as exp:
        error_title = "Consent Status Record not found from DB with given Consent Record ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to get last Consent Status Record ID from database"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("csr_id: " + str(csr_id))

    # Append ID to Consent Status Record Object
    try:
        logger.info("Append ID to Consent Status Record object: " + csr_entry.log_entry)
        csr_entry.consent_status_record_id = csr_id
    except Exception as exp:
        error_title = "Failed to append ID to Consent Status Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Appended ID to Consent Status Record object: " + csr_entry.log_entry)

    # Get Consent Status Record from DB
    try:
        cursor = csr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Consent Record not found from DB with given ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to fetch Consent Record from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("csr_entry: " + csr_entry.log_entry)

    return csr_entry


def add_csr(cr_id=None, csr_payload=None, endpoint="add_csr()"):
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if csr_payload is None:
        raise AttributeError("Provide csr_payload as parameter")

    ######
    # Base information
    ####
    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # IDs from CSR payload
    try:
        csr_surrogate_id = csr_payload['surrogate_id']
        csr_cr_id = csr_payload['cr_id']
        csr_prev_record_id = csr_payload['prev_record_id']
        csr_record_id = csr_payload['record_id']
        csr_consent_status = csr_payload['consent_status']
        csr_issued = csr_payload['iat']
    except Exception as exp:
        error_title = "Could not fetch IDs from CSR payload"
        logger.error(error_title)
        raise ApiError(code=400, title=error_title, detail=repr(exp), source=endpoint)

    # Verify that cr_id and csr_cr_id are the same
    if cr_id != csr_cr_id:
        error_title = "cr_id from URI and cr_id from payload are not identical"
        logger.error(error_title + " | cr_id from URI: " + str(cr_id) + ", cr_id from payload: " + str(csr_cr_id))
        raise ApiError(code=400, title=error_title, source=endpoint)
    else:
        logger.info("Identical IDs: cr_id from URI: " + str(cr_id) + ", cr_id from payload: " + str(csr_cr_id))

    ######
    # Sign
    ####
    # Sign CSR
    try:
        csr_signed = sign_csr(account_id=1, payload=csr_payload, endpoint=endpoint)
    except Exception as exp:
        logger.error("Could not sign Source's CSR: " + repr(exp))
        raise
    else:
        logger.info("Source CR signed")

    ###########
    # Entries #
    ###########
    # Existing Consent Record
    ###
    # Init Consent Record Object
    try:
        logger.info("Create ConsentRecord object")
        cr_entry = ConsentRecord(consent_id=cr_id)
        logger.info(cr_entry.log_entry)
    except Exception as exp:
        error_title = "Failed to create Consent Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("sink_cr_entry: " + cr_entry.log_entry)

    # Get Consent Record from DB
    try:
        cursor = cr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Consent Record not found from DB with given ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to fetch Consent Record from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("cr_entry: " + cr_entry.log_entry)

    # Get primary key of Consent Record database entry
    try:
        cr_entry_primary_key = cr_entry.id
    except Exception as exp:
        error_title = "Failed to get primary key of Consent Record database entry"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("cr_entry_primary_key: " + str(cr_entry_primary_key))

    # CSR
    try:
        csr_entry = ConsentStatusRecord(
            consent_status_record_id=csr_record_id,
            status=csr_consent_status,
            consent_status_record=csr_signed,
            consent_record_id=csr_cr_id,
            issued_at=int(csr_issued),
            prev_record_id=csr_prev_record_id,
            consent_records_id=int(cr_entry_primary_key)
        )
    except Exception as exp:
        error_title = "Failed to create Source's Consent Status Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("csr_entry: " + csr_entry.log_entry)

    ###########
    # Store #
    ###########
    # CSR

    # Get database table name for Consent Status Record
    try:
        logger.info("Get Consent Status Record table name")
        csr_table_name = csr_entry.table_name
    except Exception as exp:
        error_title = "Failed to get Consent Status Record table name"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Got Consent Status Record table name: " + str(csr_table_name))

    # Store CSR
    try:
        try:
            cursor = csr_entry.to_db(cursor=cursor)
        except Exception as exp:
            error_title = "Failed to store Consent Status Record"
            logger.error(error_title + ": " + repr(exp))
            raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
        else:
            logger.debug("csr_entry: " + csr_entry.log_entry)

        # Commit
        db.connection.commit()
    except Exception as exp:
        logger.error('Consent Status Record Commit failed: ' + repr(exp))
        db.connection.rollback()
        logger.error('--> rollback')
        raise
    else:
        logger.info("Consent Status Record commited")

    return csr_entry




