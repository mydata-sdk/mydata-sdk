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
import json
import uuid
import bcrypt  # https://github.com/pyca/bcrypt/, https://pypi.python.org/pypi/bcrypt/2.0.0

# Import the database object
from app.app_modules import db

# Import services
from app.helpers import get_custom_logger, ApiError
from app.mod_api_auth.controllers import get_account_id_by_api_key, gen_account_api_key
from app.mod_api_auth.services import delete_entry_from_apikey_sqlite_db
from app.mod_blackbox.controllers import gen_account_key
from app.mod_blackbox.services import clear_blackbox_sqlite_db, delete_entry_from_blackbox_sqlite_db
from app.mod_database.helpers import get_db_cursor, get_primary_keys_by_account_id, get_slr_ids, \
    get_slsr_ids, get_cr_ids, get_csr_ids, delete_account_from_database, get_last_slsr_id, get_consent_ids, \
    get_last_consent_id, get_consent_status_id_filter, get_consent_status_ids, get_last_csr_id

# create logger with 'spam_application'
from app.mod_database.models import AccountInfo, EventLog, ServiceLinkRecord, \
    ServiceLinkStatusRecord, ConsentRecord, ConsentStatusRecord, Account, LocalIdentityPWD, LocalIdentity, Salt

logger = get_custom_logger(__name__)


##################################
##################################
# Account
##################################
##################################
def hash_password(password=None):
    """
    Generates Hash from clear text password
    :param password:
    :return:
    """

    if password is None:
        raise AttributeError("Provide password as parameter")

    salt_str = str(bcrypt.gensalt())
    pwd_hash = bcrypt.hashpw(str(password), salt_str)

    return pwd_hash, salt_str


def create_account(first_name=None, last_name=None, username=None, password=None, endpoint="create_account()"):
    if first_name is None:
        raise AttributeError("Provide first_name as parameter")
    if last_name is None:
        raise AttributeError("Provide last_name as parameter")
    if username is None:
        raise AttributeError("Provide username as parameter")
    if password is None:
        raise AttributeError("Provide password as parameter")

    logger.info('Global identifier for Account')
    global_identifier = str(uuid.uuid4())
    logger.debug('global_identifier: ' + global_identifier)

    try:
        pwd_hash, salt_str = hash_password(password=password)
    except Exception as exp:
        error_title = "Could not generate password salt"
        logger.debug(error_title + ': ' + repr(exp))
        raise

    # DB cursor
    cursor = get_db_cursor()

    try:
        ###
        # Accounts
        logger.debug('Account')
        account = Account(global_identifyer=global_identifier)  # NOTE: activated MUST be changed to 0 if activation process is in use
        account.to_db(cursor=cursor)

        ###
        # localIdentityPWDs
        logger.debug('LocalIdentityPWD')
        local_pwd = LocalIdentityPWD(password=pwd_hash, accounts_id=account.id)
        local_pwd.to_db(cursor=cursor)

        ###
        # localIdentities
        logger.debug('LocalIdentity')
        local_identity = LocalIdentity(
            username=username,
            pwd_id=local_pwd.id,
            accounts_id=account.id
        )
        local_identity.to_db(cursor=cursor)

        ###
        # salts
        logger.debug('Salt')
        salt = Salt(
            salt=salt_str,
            identity_id=local_identity.id,
            accounts_id=account.id
        )
        salt.to_db(cursor=cursor)

        ###
        # AccountInfo
        logger.debug('AccountInfo')
        info = AccountInfo(
            firstname=first_name,
            lastname=last_name,
            account_id=account.id
        )
        cursor = info.to_db(cursor=cursor)

        ##
        try:
            logger.info("Generating Key for Account")
            kid = gen_account_key(account_id=account.id)
        except Exception as exp:
            error_title = "Could not generate Key for Account"
            logger.debug(error_title + ': ' + repr(exp))
            raise
        else:
            logger.info("Generated Key for Account with Key ID: " + str(kid))

        try:
            logger.info("Generating API Key for Account")
            api_key = gen_account_api_key(account_id=account.id)
        except Exception as exp:
            error_title = "Could not generate API Key for Account"
            logger.debug(error_title + ': ' + repr(exp))
            raise
        else:
            logger.info("Generated API Key: " + str(api_key))

        ###
        # Commit MySql data
        db.connection.commit()
    except Exception as exp:
        error_title = "Could not create Account"
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        logger.error(error_title)
        db.connection.rollback()
        raise
    else:
        logger.debug('Account created')

        data = cursor.fetchall()
        logger.debug('data: ' + repr(data))

        logger.info('Created Account: ' + account.log_entry)
        return account, account.id


def delete_account(account_id=None):
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    try:
        account_id = str(account_id)
    except Exception:
        raise TypeError("account_id MUST be str, not " + str(type(account_id)))

    # Delete account from MySQL database
    try:
        logger.info("Deleting Account data from MySQL database")
        delete_account_from_database(account_id=account_id)
    except Exception as exp:
        logger.error('Could not mark Account as deleted: ' + repr(exp))
        raise
    else:
        logger.info("Account marked as deleted")

    try:
        logger.info("Deleting Account data from Blackbox database")
        delete_entry_from_blackbox_sqlite_db(account_id=account_id)
    except Exception as exp:
        logger.error("Could not delete Account data from Blackbox Database: " + repr(exp))
        raise
    else:
        logger.info("Account data deleted from Blackbox Database")

    try:
        logger.info("Deleting Account data from ApiKey database")
        delete_entry_from_apikey_sqlite_db(account_id=account_id)
    except Exception as exp:
        logger.error("Could not delete Account data from ApiKey Database: " + repr(exp))
        raise
    else:
        logger.info("Account data deleted from ApiKey Database")
        return True


def get_account(account_id=None, cursor=None):
    """
    Get one account entry from database by Account ID
    :param account_id:
    :return: Particular dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        logger.info("Creating Account object")
        db_entry_object = Account(id=account_id)
    except Exception as exp:
        error_title = "Failed to create Account object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("Account object created: " + db_entry_object.log_entry)

    # Get Account from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch Account from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("Account fetched")
        logger.info("Account fetched from db: " + db_entry_object.log_entry)

    return db_entry_object


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
            error_detail = "Authenticated Account ID not matching with Account ID that was provided with request"
    elif account_id_to_compare is not None:
        logger.info("account_id_to_compare provided as parameter")
        error_detail = "Account ID in payload not matching with Account ID that was provided with request"

    # Check if Account IDs are matching
    logger.info("Check if Account IDs are matching")
    logger.info("account_id: " + str(account_id))
    logger.info("account_id_to_compare: " + str(account_id_to_compare))
    if str(account_id) != str(account_id_to_compare):
        logger.error(error_detail)
        raise ApiError(
            code=403,
            title="Forbidden",
            source=endpoint,
            detail=error_detail
        )
    else:
        logger.info("Account IDs are matching")
        logger.info("account_id: " + str(account_id))
        logger.info("account_id_to_compare: " + str(account_id_to_compare))

    return True


def export_account(account_id=None):
    """
    Export Account as JSON presentation
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    export = {
        "type": "Account",
        "id": account_id,
        "attributes": {}
    }

    return export


##################################
##################################
# AccountInfo
##################################
##################################
def get_account_info(account_id=None, id=None, cursor=None):
    """
    Get one AccountInfo entry from database
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
        logger.info("Creating AccountInfo object")
        db_entry_object = AccountInfo(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create AccountInfo object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("AccountInfo object created: " + db_entry_object.log_entry)

    # Get AccountInfo from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch AccountInfo from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("AccountInfo fetched")
        logger.info("AccountInfo fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_account_infos(account_id=None):
    """
    Get all AccountInfo -entries related to account
    :param account_id:
    :return: List of AccountInfo dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create db_entry_object")
    db_entry_object = AccountInfo()
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

    # Get primary keys for AccountInfo
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get AccountInfo objects from database
    logger.info("Get AccountInfo objects from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting AccountInfo with info_id: " + str(id))
        db_entry_dict = get_account_info(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("AccountInfo object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def update_account_info(account_id=None, id=None, attributes=None, cursor=None):
    """
    Update one AccountInfo entry at database
    :param account_id:
    :param id:
    :return: AccountInfo dict
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
        db_entry_object = AccountInfo(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create AccountInfo object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("AccountInfo object created: " + db_entry_object.log_entry)

    # Get AccountInfo from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch AccountInfo from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("AccountInfo fetched")
        logger.debug("AccountInfo fetched from db: " + db_entry_object.log_entry)

    # Update AccountInfo object
    if len(attributes) == 0:
        logger.info("Empty attributes dict provided. Nothing to update.")
        return db_entry_object
    else:
        logger.info("Attributes provided")
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

    if "avatar" in attributes:
        logger.info("Updating avatar")
        old_value = str(db_entry_object.avatar)
        new_value = str(attributes.get("avatar", "None"))
        logger.debug("Updating: " + old_value + " --> " + new_value)
        db_entry_object.avatar = new_value
        logger.info(db_entry_object.log_entry)

    # Store updates
    try:
        cursor = db_entry_object.update_db(cursor=cursor)
        ###
        # Commit
        db.connection.commit()
    except Exception as exp:
        error_title = "Failed to update AccountInfo to DB"
        logger.error(error_title + ": " + repr(exp))
        logger.debug('commit failed: ' + repr(exp))
        logger.debug('--> rollback')
        db.connection.rollback()
        raise
    else:
        logger.debug("Committed")
        logger.info("AccountInfo updated")
        logger.info(db_entry_object.log_entry)

    return db_entry_object


##################################
###################################
# Event logs
##################################
##################################
def get_event_log(account_id=None, id=None, cursor=None):
    """
    Get one event_log entry from database by Account ID and ID
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
        db_entry_object = EventLog(account_id=account_id, id=id)
    except Exception as exp:
        error_title = "Failed to create event_log object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("event_log object created: " + db_entry_object.log_entry)

    # Get event_log from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch event_log from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("event_log fetched")
        logger.info("event_log fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def get_event_logs(account_id=None):
    """
    Get all event_log -entries related to account
    :param account_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get table name
    logger.info("Create event_log")
    db_entry_object = EventLog()
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

    # Get primary keys for event_log
    try:
        cursor, id_list = get_primary_keys_by_account_id(cursor=cursor, account_id=account_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get event_log from database
    logger.info("Get event_log from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting event_log with event_log_id: " + str(id))
        db_entry_dict = get_event_log(account_id=account_id, id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("event_log object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


##################################
##################################
# Service Link Records
##################################
##################################
def account_get_slr(account_id=None, slr_id=None, cursor=None):
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


def account_get_slrs(account_id=None):
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
        db_entry_dict = account_get_slr(account_id=account_id, slr_id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("slr object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


##################################
##################################
# Service Link Status Records
##################################
##################################
def account_get_slsr(account_id=None, slr_id=None, slsr_id=None, cursor=None):
    """
    Get one slsr entry from database by Account ID and ID
    :param slr_id:
    :param slsr_id:
    :return: dict
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if slsr_id is None:
        raise AttributeError("Provide slsr_id as parameter")
    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    # Check if slr can be found with account_id and slr_id
    try:
        slr = account_get_slr(account_id=account_id, slr_id=slr_id)
    except StandardError as exp:
        logger.error(repr(exp))
        raise
    except Exception as exp:
        func_data = {'account_id': account_id, 'slr_id': slr_id}
        title = "No SLR with: " + json.dumps(func_data)
        logger.error(title)
        raise StandardError(title + ": " + repr(exp))
    else:
        logger.info("Found SLR: " + repr(slr))

    try:
        db_entry_object = ServiceLinkStatusRecord(service_link_status_record_id=slsr_id, service_link_record_id=slr_id)
    except Exception as exp:
        error_title = "Failed to create slsr object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("slsr object created: " + db_entry_object.log_entry)

    # Get slsr from DB
    try:
        logger.info("Get slsr from DB")
        cursor = db_entry_object.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Service Link Status Record not found with provided information."
        error_detail = "Service Link Record ID was {} and Service Link Status Record ID was {}.".format(slr_id, slsr_id)
        logger.error(error_title + " " + error_detail + ": " + repr(exp))
        raise IndexError(error_detail)
    except Exception as exp:
        error_title = "Failed to fetch slsr from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("slsr fetched")
        logger.info("slsr fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def account_get_slsrs(account_id=None, slr_id=None):
    """
    Get all slsr -entries related to service link record
    :param account_id:
    :param slr_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")

    # Check if slr can be found with account_id and slr_id
    try:
        slr = account_get_slr(account_id=account_id, slr_id=slr_id)
    except StandardError as exp:
        logger.error(repr(exp))
        raise
    except Exception as exp:
        func_data = {'account_id': account_id, 'slr_id': slr_id}
        title = "No SLR with: " + json.dumps(func_data)
        logger.error(title)
        raise IndexError(title + ": " + repr(exp))
    else:
        logger.info("Found SLR: " + repr(slr))

    # Get table name
    logger.info("Create slsr")
    db_entry_object = ServiceLinkStatusRecord()
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

    # Get primary keys for slsr
    try:
        cursor, id_list = get_slsr_ids(cursor=cursor, slr_id=slr_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get slsrs from database
    logger.info("Get slsrs from database")
    db_entry_list = []
    for id in id_list:
        # TODO: try-except needed?
        logger.info("Getting slsr with account_id: " + str(account_id) + " slr_id: " + str(slr_id) + " slsr_id: " + str(id))
        db_entry_dict = account_get_slsr(account_id=account_id, slr_id=slr_id, slsr_id=id)
        db_entry_list.append(db_entry_dict)
        logger.info("slsr object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def account_get_last_slr_status(account_id=None, slr_id=None, endpoint="get_last_slr_status()"):
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get DB cursor
    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise ApiError(code=500, title="Failed to get database cursor", detail=repr(exp), source=endpoint)

    # Init ServiceLinkRecord Object
    try:
        logger.info("Create ServiceLinkRecord object")
        slr_entry = ServiceLinkRecord(service_link_record_id=slr_id, account_id=account_id)
        logger.info(slr_entry.log_entry)
    except Exception as exp:
        error_title = "Failed to create Service Link Record object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("slr_entry: " + slr_entry.log_entry)

    # Get ServiceLinkRecord from DB
    try:
        cursor = slr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Service Link Status Record not found with provided information."
        error_detail = "Account ID was {} and Service Link Record ID was {}.".format(account_id, slr_id)
        logger.error(error_title + " " + error_detail + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=error_detail, source=endpoint)
    except Exception as exp:
        error_title = "Failed to fetch Service Link Record from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=str(exp.message), source=endpoint)
    else:
        logger.debug("slr_entry: " + slr_entry.log_entry)

    # Create ServiceLinkStatusRecord object
    try:
        slsr_entry = ServiceLinkStatusRecord()
    except Exception as exp:
        error_title = "Failed to create ServiceLinkStatusRecord object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("slsr_entry: " + slsr_entry.log_entry)

    # Get database table name for ServiceLinkStatusRecord
    try:
        logger.info("Get ServiceLinkStatusRecord table name")
        slsr_table_name = slsr_entry.table_name
    except Exception as exp:
        error_title = "Failed to get ServiceLinkStatusRecord table name"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Got ServiceLinkStatusRecord table name: " + str(slsr_table_name))

    # Get ServiceLinkStatusRecord ID
    try:
        cursor, slsr_id = get_last_slsr_id(cursor=cursor, slr_id=slr_id, table_name=slsr_table_name)
    except IndexError as exp:
        error_title = "ServiceLinkStatusRecord not found from DB with given Consent Record ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to get last ServiceLinkStatusRecord ID from database"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("slsr_id: " + str(slsr_id))

    # Append ID to ServiceLinkStatusRecord Object
    try:
        logger.info("Append ID to ServiceLinkStatusRecord object: " + slsr_entry.log_entry)
        slsr_entry.consent_status_record_id = slsr_id
    except Exception as exp:
        error_title = "Failed to append ID to ServiceLinkStatusRecord object"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.info("Appended ID to ServiceLinkStatusRecord object: " + slsr_entry.log_entry)

    # Get ServiceLinkStatusRecord from DB
    try:
        cursor = slsr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "ServiceLinkStatusRecord not found from DB with given ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to fetch ServiceLinkStatusRecord from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("slsr_entry: " + slsr_entry.log_entry)

    return slsr_entry.to_api_dict


##################################
##################################
# Consents
##################################
##################################
def account_get_cr(cr_id="", surrogate_id="", slr_id="", subject_id="", consent_pair_id="", account_id="", cursor=None):
    """
    Get Consent Record entry
    :param account_id:
    :param slr_id:
    :return: dict
    """
    try:
        cr_id = str(cr_id)
    except Exception:
        raise TypeError("cr_id MUST be str, not " + str(type(cr_id)))
    try:
        surrogate_id = str(surrogate_id)
    except Exception:
        raise TypeError("surrogate_id MUST be str, not " + str(type(surrogate_id)))
    try:
        slr_id = str(slr_id)
    except Exception:
        raise TypeError("slr_id MUST be str, not " + str(type(slr_id)))
    try:
        subject_id = str(subject_id)
    except Exception:
        raise TypeError("subject_id MUST be str, not " + str(type(subject_id)))
    try:
        consent_pair_id = str(consent_pair_id)
    except Exception:
        raise TypeError("consent_pair_id MUST be str, not " + str(type(consent_pair_id)))
    try:
        account_id = str(account_id)
    except Exception:
        raise TypeError("account_id MUST be str, not " + str(type(account_id)))

    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = ConsentRecord(
            consent_id=cr_id,
            surrogate_id=surrogate_id,
            service_link_record_id=slr_id,
            subject_id=subject_id,
            consent_pair_id=consent_pair_id,
            accounts_id=account_id
        )
    except Exception as exp:
        error_title = "Failed to create ConsentRecord object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("ConsentRecord object created: " + db_entry_object.log_entry)

    # Get slr from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch ConsentRecord from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("ConsentRecord fetched")
        logger.debug("ConsentRecord fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def account_get_crs(surrogate_id="", slr_id="", subject_id="", consent_pair_id="", account_id="", status_id="", consent_pairs=False):
    """
    Get Consent Records

    :param surrogate_id:
    :param slr_id:
    :param subject_id:
    :param consent_pair_id:
    :param account_id:
    :return:
    """
    try:
        surrogate_id = str(surrogate_id)
    except Exception:
        raise TypeError("surrogate_id MUST be str, not " + str(type(surrogate_id)))
    try:
        slr_id = str(slr_id)
    except Exception:
        raise TypeError("slr_id MUST be str, not " + str(type(slr_id)))
    try:
        subject_id = str(subject_id)
    except Exception:
        raise TypeError("subject_id MUST be str, not " + str(type(subject_id)))
    try:
        consent_pair_id = str(consent_pair_id)
    except Exception:
        raise TypeError("consent_pair_id MUST be str, not " + str(type(consent_pair_id)))
    try:
        account_id = str(account_id)
    except Exception:
        raise TypeError("account_id MUST be str, not " + str(type(account_id)))
    try:
        status_id = str(status_id)
    except Exception:
        raise TypeError("status_id MUST be str, not " + str(type(status_id)))
    try:
        consent_pairs = bool(consent_pairs)
    except Exception:
        raise TypeError("consent_pairs MUST be bool, not " + str(type(consent_pairs)))

    logger.info("surrogate_id: " + surrogate_id)
    logger.info("slr_id: " + slr_id)
    logger.info("subject_id: " + subject_id)
    logger.info("consent_pair_id: " + consent_pair_id)
    logger.info("account_id: " + account_id)
    logger.info("status_id: " + status_id)
    if consent_pairs:
        logger.info("consent_pairs: True")
    else:
        logger.info("consent_pairs: False")

    # Get table name
    logger.info("Create ConsentRecord object")
    db_entry_object = ConsentRecord()
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
        cursor, id_list = get_consent_ids(
            cursor=cursor,
            surrogate_id=surrogate_id,
            slr_id=slr_id,
            subject_id=subject_id,
            consent_pair_id=consent_pair_id,
            account_id=account_id,
            table_name=table_name
        )
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get ConsentRecords from database
    logger.info("Get ConsentRecords from database")
    cr_list = []
    logger.info("Getting ConsentRecords")
    for entry_id in id_list:
        # TODO: try-except needed?
        logger.info("Getting ConsentRecord with cr_id: " + str(entry_id))
        db_entry_dict = account_get_cr(cr_id=entry_id, account_id=account_id)
        cr_list.append(db_entry_dict)
        logger.info("ConsentRecord object added to list: " + json.dumps(db_entry_dict))

    if consent_pairs:
        logger.info("Getting Consent Record pairs")
        for entry_id in id_list:
            # TODO: try-except needed?
            logger.info("Getting ConsentRecord with consent_pair_id: " + str(entry_id))
            db_entry_dict = account_get_cr(consent_pair_id=entry_id, account_id=account_id)
            cr_list.append(db_entry_dict)
            logger.info("ConsentRecord object added to list: " + json.dumps(db_entry_dict))

    logger.info("ConsentRecords fetched: " + json.dumps(cr_list))

    return cr_list


def account_get_last_cr(surrogate_id="", slr_id="", subject_id="", consent_pair_id="", account_id="", status_id="", consent_pairs=False):
    """
    Get Consent Records

    :param surrogate_id:
    :param slr_id:
    :param subject_id:
    :param consent_pair_id:
    :param account_id:
    :return:
    """
    try:
        surrogate_id = str(surrogate_id)
    except Exception:
        raise TypeError("surrogate_id MUST be str, not " + str(type(surrogate_id)))
    try:
        slr_id = str(slr_id)
    except Exception:
        raise TypeError("slr_id MUST be str, not " + str(type(slr_id)))
    try:
        subject_id = str(subject_id)
    except Exception:
        raise TypeError("subject_id MUST be str, not " + str(type(subject_id)))
    try:
        consent_pair_id = str(consent_pair_id)
    except Exception:
        raise TypeError("consent_pair_id MUST be str, not " + str(type(consent_pair_id)))
    try:
        account_id = str(account_id)
    except Exception:
        raise TypeError("account_id MUST be str, not " + str(type(account_id)))
    try:
        status_id = str(status_id)
    except Exception:
        raise TypeError("status_id MUST be str, not " + str(type(status_id)))
    try:
        consent_pairs = bool(consent_pairs)
    except Exception:
        raise TypeError("consent_pairs MUST be bool, not " + str(type(consent_pairs)))

    logger.info("surrogate_id: " + surrogate_id)
    logger.info("slr_id: " + slr_id)
    logger.info("subject_id: " + subject_id)
    logger.info("consent_pair_id: " + consent_pair_id)
    logger.info("account_id: " + account_id)
    logger.info("status_id: " + status_id)
    if consent_pairs:
        logger.info("consent_pairs: True")
    else:
        logger.info("consent_pairs: False")

    # Get table name
    logger.info("Create ConsentRecord object")
    db_entry_object = ConsentRecord()
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
        cursor, id_list = get_last_consent_id(
            cursor=cursor,
            surrogate_id=surrogate_id,
            slr_id=slr_id,
            subject_id=subject_id,
            consent_pair_id=consent_pair_id,
            account_id=account_id,
            table_name=table_name
        )
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get ConsentRecords from database
    logger.info("Get ConsentRecords from database")
    cr_list = []
    logger.info("Getting ConsentRecords")
    for entry_id in id_list:
        # TODO: try-except needed?
        logger.info("Getting ConsentRecord with cr_id: " + str(entry_id))
        db_entry_dict = account_get_cr(cr_id=entry_id, account_id=account_id)
        cr_list.append(db_entry_dict)
        logger.info("ConsentRecord object added to list: " + json.dumps(db_entry_dict))

    if consent_pairs:
        logger.info("Getting Consent Record pairs")
        for entry_id in id_list:
            # TODO: try-except needed?
            logger.info("Getting ConsentRecord with consent_pair_id: " + str(entry_id))
            db_entry_dict = account_get_cr(consent_pair_id=entry_id, account_id=account_id)
            cr_list.append(db_entry_dict)
            logger.info("ConsentRecord object added to list: " + json.dumps(db_entry_dict))

    logger.info("ConsentRecords fetched: " + json.dumps(cr_list))

    return cr_list


def account_get_csr(csr_id="", cr_id="", prev_record_id="", account_id="", cursor=None):
    """
    Get Consent Record entry

    :param csr_id: 
    :param cr_id: 
    :param prev_record_id: 
    :param account_id: 
    :param cursor: 
    :return: dict
    """
    try:
        cr_id = str(cr_id)
    except Exception:
        raise TypeError("cr_id MUST be str, not " + str(type(cr_id)))
    try:
        csr_id = str(csr_id)
    except Exception:
        raise TypeError("csr_id MUST be str, not " + str(type(csr_id)))
    try:
        prev_record_id = str(prev_record_id)
    except Exception:
        raise TypeError("prev_record_id MUST be str, not " + str(type(prev_record_id)))
    try:
        account_id = str(account_id)
    except Exception:
        raise TypeError("account_id MUST be str, not " + str(type(account_id)))

    if cursor is None:
        # Get DB cursor
        try:
            cursor = get_db_cursor()
        except Exception as exp:
            logger.error('Could not get database cursor: ' + repr(exp))
            raise

    try:
        db_entry_object = ConsentStatusRecord(
            consent_record_id=cr_id,
            consent_status_record_id=csr_id,
            prev_record_id=prev_record_id,
            accounts_id=account_id
        )
    except Exception as exp:
        error_title = "Failed to create ConsentRecord object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("ConsentRecord object created: " + db_entry_object.log_entry)

    # Get slr from DB
    try:
        cursor = db_entry_object.from_db(cursor=cursor)
    except Exception as exp:
        error_title = "Failed to fetch ConsentRecord from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("ConsentRecord fetched")
        logger.debug("ConsentRecord fetched from db: " + db_entry_object.log_entry)

    return db_entry_object.to_api_dict


def account_get_csrs(account_id=None, consent_id=None, status_id=""):
    """
    Get all consent status record entries related to Consent Record
    :param account_id:
    :param consent_id:
    :return: List of dicts
    """
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if consent_id is None:
        raise AttributeError("Provide consent_id as parameter")
    if status_id is None:
        raise AttributeError("Provide status_id as parameter")

    # Get table name
    logger.info("Create Consent Status Record object")
    db_entry_object = ConsentStatusRecord()
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

    # Get primary key filter
    try:
        cursor, filter_id = get_consent_status_id_filter(cursor=cursor, csr_id=status_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get primary keys for Consent Status Records
    try:
        cursor, id_list = get_consent_status_ids(cursor=cursor, cr_id=consent_id, primary_key_filter=filter_id, table_name=table_name)
    except Exception as exp:
        logger.error('Could not get primary key list: ' + repr(exp))
        raise

    # Get Consent Status Records from database
    logger.info("Get Consent Status Records from database")
    db_entry_list = []
    for entry_id in id_list:
        # TODO: try-except needed?
        logger.info("Getting Consent Status Record with account_id: " + str(account_id) + " consent_id: " + str(
            consent_id) + " csr_id: " + str(entry_id))
        db_entry_dict = account_get_csr(account_id=account_id, cr_id=consent_id, csr_id=entry_id)
        db_entry_list.append(db_entry_dict)
        logger.info("Consent Status Records object added to list: " + json.dumps(db_entry_dict))

    return db_entry_list


def account_get_last_cr_status(consent_id=None, account_id="", endpoint="get_last_cr_status()"):
    if consent_id is None:
        raise AttributeError("Provide consent_id as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")

    # Get DB cursor
    try:
        logger.info("Getting database cursor")
        cursor = get_db_cursor()
    except Exception as exp:
        logger.error('Could not get database cursor: ' + repr(exp))
        raise

    # Init Consent Record Object
    try:
        logger.info("Create ConsentRecord object")
        cr_entry = ConsentRecord(consent_id=consent_id)
        logger.info(cr_entry.log_entry)
    except Exception as exp:
        error_title = "Failed to create Consent Record object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("ConsentRecord object: " + cr_entry.log_entry)

    # Get Consent Record from DB
    try:
        logger.info("Getting Consent Record from DB")
        cursor = cr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Consent Record not found from DB with given ID"
        logger.error(error_title + ": " + repr(exp))
        raise
    except Exception as exp:
        error_title = "Failed to fetch Consent Record from DB"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("cr_entry: " + cr_entry.log_entry)

    # Create Consent Status Record object
    try:
        logger.info("Creating Consent Status Record object")
        csr_entry = ConsentStatusRecord()
    except Exception as exp:
        error_title = "Failed to create Consent Status Record object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("Consent Status Record object: " + csr_entry.log_entry)

    # Get Consent Status Record ID
    try:
        logger.info("Getting ID of last Consent Status Record")
        cursor, csr_id = get_last_csr_id(cursor=cursor, consent_id=consent_id, account_id=account_id, table_name=csr_entry.table_name)
    except IndexError as exp:
        error_title = "Consent Status Record not found from DB with given Consent Record ID"
        logger.error(error_title + ": " + repr(exp))
        raise
    except Exception as exp:
        error_title = "Failed to get last Consent Status Record ID from database"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.debug("Consent Status Record ID: " + str(csr_id))

    # Append IDs to Consent Status Record Object
    try:
        logger.info("Appending IDs to Consent Status Record object")
        csr_entry.consent_status_record_id = csr_id
        csr_entry.accounts_id = account_id
    except Exception as exp:
        error_title = "Failed to append IDs to Consent Status Record object"
        logger.error(error_title + ": " + repr(exp))
        raise
    else:
        logger.info("Appended IDs to Consent Status Record object: " + csr_entry.log_entry)

    # Get Consent Status Record from DB
    try:
        logger.info("Getting Consent Status Record from DB")
        cursor = csr_entry.from_db(cursor=cursor)
    except IndexError as exp:
        error_title = "Consent Status Record not found from DB with given ID"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=404, title=error_title, detail=repr(exp), source=endpoint)
    except Exception as exp:
        error_title = "Failed to fetch Consent Status Record from DB"
        logger.error(error_title + ": " + repr(exp))
        raise ApiError(code=500, title=error_title, detail=repr(exp), source=endpoint)
    else:
        logger.debug("Consent Status Record object: " + csr_entry.log_entry)

    return csr_entry.to_api_dict



