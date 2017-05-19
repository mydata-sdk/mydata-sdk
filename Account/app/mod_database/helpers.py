# -*- coding: utf-8 -*-

# Import dependencies
import logging

from flask import current_app
from app.helpers import get_custom_logger

# Import the database object
from app.app_modules import db

logger = get_custom_logger(__name__)


def log_query(sql_query=None, arguments=None):
    logger.info("Executing")
    if sql_query is None:
        raise AttributeError("Provide sql_query as parameter")
    if arguments is None:
        raise AttributeError("Provide arguments as parameter")

    logger.debug('sql_query: ' + repr(sql_query))

    for index in range(len(arguments)):
        logger.debug("arguments[" + str(index) + "]: " + str(arguments[index]))

    logger.debug('SQL query to execute: ' + repr(sql_query % arguments))


def get_db_cursor():
    logger.info("Executing")
    try:
        cursor = db.connection.cursor()
    except Exception as exp:
        logger.debug('db.connection.cursor(): ' + repr(exp))
        raise RuntimeError('Could not get cursor for database connection')
    else:
        logger.debug('DB cursor at ' + repr(cursor))
        return cursor


def execute_sql_insert(cursor, sql_query):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    INSERT to MySQL
    """
    logger.info("Executing")

    last_id = ""

    if current_app.config["SUPER_DEBUG"]:
        logger.debug('sql_query: ' + repr(sql_query))

    try:
        # Should be done like here: http://stackoverflow.com/questions/3617052/escape-string-python-for-mysql/27575399#27575399
        cursor.execute(sql_query)

    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        last_id = str(cursor.lastrowid)
    except Exception as exp:
        logger.debug('cursor.lastrowid not found: ' + repr(exp))
        raise
    else:
        logger.debug('cursor.lastrowid: ' + last_id)

        return cursor, last_id


def execute_sql_insert_2(cursor, sql_query, arguments):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    INSERT to MySQL
    """
    logger.info("Executing")

    last_id = ""

    log_query(sql_query=sql_query, arguments=arguments)

    try:
        # Should be done like here: http://stackoverflow.com/questions/3617052/escape-string-python-for-mysql/27575399#27575399
        cursor.execute(sql_query, (arguments))
        logger.debug("Executed SQL query: " + str(cursor._last_executed))
        logger.debug("Affected rows: " + str(cursor.rowcount))
    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        last_id = str(cursor.lastrowid)
    except Exception as exp:
        logger.debug('cursor.lastrowid not found: ' + repr(exp))
        raise
    else:
        logger.debug('cursor.lastrowid: ' + last_id)

        return cursor, last_id


def execute_sql_update(cursor, sql_query, arguments):
    """
    :param arguments:
    :param cursor:
    :param sql_query:
    :return: cursor:

    INSERT to MySQL
    """
    logger.info("Executing")

    logger.debug('sql_query: ' + str(sql_query))

    for index in range(len(arguments)):
        logger.debug("arguments[" + str(index) + "]: " + str(arguments[index]))

    try:
        # Should be done like here: http://stackoverflow.com/questions/3617052/escape-string-python-for-mysql/27575399#27575399
        cursor.execute(sql_query, (arguments))
        logger.debug("Executed SQL query: " + str(cursor._last_executed))
        logger.debug("Affected rows SQL query: " + str(cursor.rowcount))
    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise
    else:
        logger.debug('db entry updated')
        return cursor


def execute_sql_select(cursor=None, sql_query=None):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    SELECT from MySQL
    """
    logger.info("Executing")

    if current_app.config["SUPER_DEBUG"]:
        logger.debug('sql_query: ' + repr(sql_query))

    try:
        cursor.execute(sql_query)

    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        data = cursor.fetchall()
    except Exception as exp:
        logger.debug('cursor.fetchall() failed: ' + repr(exp))
        data = 'No content'

    if current_app.config["SUPER_DEBUG"]:
        logger.debug('data ' + repr(data))

    return cursor, data


def execute_sql_select_2(cursor=None, sql_query=None, arguments=None):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    SELECT from MySQL
    """
    logger.info("Executing")

    log_query(sql_query=sql_query, arguments=arguments)

    try:

        cursor.execute(sql_query, (arguments))
        logger.debug("Executed SQL query: " + str(cursor._last_executed))
        logger.debug("Affected rows: " + str(cursor.rowcount))
    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        data = cursor.fetchall()
    except Exception as exp:
        logger.debug('cursor.fetchall() failed: ' + repr(exp))
        data = 'No content'

    logger.debug('data ' + repr(data))

    return cursor, data


def execute_sql_count(cursor=None, sql_query=None):
    """
    :param cursor:
    :param sql_query:
    :return: cursor:
    :return: last_id:

    SELECT from MySQL
    """
    logger.info("Executing")

    consent_count = 0

    if current_app.config["SUPER_DEBUG"]:
        logger.debug('sql_query: ' + repr(sql_query))

    try:
        cursor.execute(sql_query)

    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        raise

    try:
        data = cursor.fetchone()
        if current_app.config["SUPER_DEBUG"]:
            logger.debug('data: ' + repr(data))

        consent_count = int(data[0])

    except Exception as exp:
        logger.debug('cursor.fetchone() failed: ' + repr(exp))

    if current_app.config["SUPER_DEBUG"]:
        logger.debug('data ' + repr(data))

    return cursor, consent_count


def drop_table_content():
    """
    http://stackoverflow.com/questions/5452760/truncate-foreign-key-constrained-table/5452798#5452798

    Drop table content
    """
    logger.info("Executing")

    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.debug('Could not get db cursor: ' + repr(exp))
        raise

    sql_query = "SELECT Concat('TRUNCATE TABLE ',table_schema,'.',TABLE_NAME, ';') " \
                "FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('MyDataAccount');"

    # sql_query1 = "SELECT Concat('DELETE FROM ',table_schema,'.',TABLE_NAME, '; ALTER TABLE ',table_schema,'.',TABLE_NAME, ' AUTO_INCREMENT = 1;') " \
    #             "FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('MyDataAccount');"
    # TODO: Remove two upper rows

    try:
        cursor.execute(sql_query)
    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        db.connection.rollback()
        raise
    else:
        sql_queries = cursor.fetchall()
        logger.debug("Fetched sql_queries: " + repr(sql_queries))

        try:
            logger.debug("SET FOREIGN_KEY_CHECKS = 0;")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")

            for query in sql_queries:
                logger.debug("Executing: " + str(query[0]))
                sql_query = str(query[0])
                cursor.execute(sql_query)
        except Exception as exp:
            logger.debug('Error in SQL query execution: ' + repr(exp))
            db.connection.rollback()

            logger.debug("SET FOREIGN_KEY_CHECKS = 1;")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")

            raise
        else:
            db.connection.commit()
            logger.debug("Committed")

            logger.debug("SET FOREIGN_KEY_CHECKS = 1;")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")

            return True


def mark_account_as_deleted(account_id=None):
    """
    Marks all entries related to Account as deleted
    """
    logger.info("Executing")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if not isinstance(account_id, int):
        try:
            account_id = int(account_id)
        except Exception as exp:
            logger.error("account_id has wrong type: " + repr(type(account_id)) + ' - ' + repr(exp))
            raise TypeError("account_id MUST be int")
        else:
            logger.info("account_id: " + str(account_id))

    try:
        cursor = get_db_cursor()
    except Exception as exp:
        logger.debug('Could not get db cursor: ' + repr(exp))
        raise

    # sql_query = "SELECT Concat('UPDATE ',table_schema,'.',TABLE_NAME, ';') " \
    #             "FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('MyDataAccount');"

    # TODO: This might be good to implement with separate arguments
    sql_query_for_account_table = "UPDATE MyDataAccount.Accounts SET deleted = 1 WHERE id = {0};".format(account_id)

    sql_query = "SELECT Concat('UPDATE ',table_schema,'.',TABLE_NAME, ' SET deleted = 1 ', 'WHERE Accounts_id = %s',';') " \
                "FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('MyDataAccount');"

    arguments = (
        int(account_id),
    )

    # sql_query1 = "SELECT Concat('DELETE FROM ',table_schema,'.',TABLE_NAME, '; ALTER TABLE ',table_schema,'.',TABLE_NAME, ' AUTO_INCREMENT = 1;') " \
    #             "FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('MyDataAccount');"
    # TODO: Remove two upper rows

    try:
        log_query(sql_query=sql_query, arguments=arguments)
        cursor.execute(sql_query, (arguments))
    except Exception as exp:
        logger.debug('Error in SQL query execution: ' + repr(exp))
        db.connection.rollback()
        raise
    else:
        sql_queries = cursor.fetchall()
        logger.debug("Fetched sql_queries: " + repr(sql_queries))

        try:
            for query in sql_queries:
                if "MyDataAccount.Accounts" in query[0]:  # MyDataAccount.Accounts table has to skipped here because missing table column "Accounts_id"
                    logger.debug("Skipping MyDataAccount.Accounts table because missing table column Accounts_id")
                else:
                    logger.debug("Executing: " + str(query[0]))
                    sql_query = str(query[0])
                    cursor.execute(sql_query)

            logger.debug("Executing: " + str(sql_query_for_account_table))  # Handling MyDataAccount.Accounts
            cursor.execute(sql_query_for_account_table)
        except Exception as exp:
            logger.debug('Error in SQL query execution: ' + repr(exp))
            db.connection.rollback()
            raise
        else:
            db.connection.commit()
            logger.debug("Committed")
            return True


def get_primary_keys_by_account_id(cursor=None, account_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT id " \
                "FROM " + table_name + " " \
                "WHERE Accounts_id LIKE %s;"

    arguments = (
        '%' + str(account_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i])

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_slr_ids(cursor=None, account_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if account_id is None:
        raise AttributeError("Provide account_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT serviceLinkRecordId " \
                "FROM " + table_name + " " \
                "WHERE Accounts_id LIKE %s;"

    arguments = (
        '%' + str(account_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))
        #logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data)
        logger.info("Got data_list: " + repr(data_list))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i][0])
        logger.info("Formatted data_list: " + repr(data_list))

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_slr_ids_by_service(cursor=None, service_id=None, surrogate_id="", table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if service_id is None:
        raise AttributeError("Provide service_id as parameter")
    if surrogate_id is None:
        raise AttributeError("Provide surrogate_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT serviceLinkRecordId " \
                "FROM " + table_name + " " \
                "WHERE serviceId LIKE %s AND surrogateId LIKE %s;"

    arguments = (
        '%' + str(service_id) + '%',
        '%' + str(surrogate_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))
        #logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data)
        logger.info("Got data_list: " + repr(data_list))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i][0])
        logger.info("Formatted data_list: " + repr(data_list))

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_slsr_ids(cursor=None, slr_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT serviceLinkStatusRecordId " \
                "FROM " + table_name + " " \
                "WHERE serviceLinkRecordId LIKE %s;"

    arguments = (
        '%' + str(slr_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i])

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_last_slsr_id(cursor=None, slr_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT serviceLinkStatusRecordId " \
                "FROM " + table_name + " " \
                "WHERE serviceLinkRecordId LIKE %s " \
                "ORDER BY id DESC " \
                "LIMIT 1;"

    arguments = (
        '%' + str(slr_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        entry_id = str(data_list[0])
        logger.info("Got entry_id: " + repr(entry_id))

        return cursor, entry_id


def get_cr_ids(cursor=None, slr_id=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if slr_id is None:
        raise AttributeError("Provide slr_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    sql_query = "SELECT consentRecordId " \
                "FROM " + table_name + " " \
                "WHERE serviceLinkRecordId LIKE %s;"

    arguments = (
        '%' + str(slr_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i])

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_csr_ids(cursor=None, cr_id=None, csr_primary_key=None, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")
    if csr_primary_key is None:
        sql_query = "SELECT consentStatusRecordId " \
                    "FROM " + table_name + " " \
                    "WHERE consentRecordId LIKE %s;"

        arguments = (
            '%' + str(cr_id) + '%',
        )
    else:
        sql_query = "SELECT consentStatusRecordId " \
                    "FROM " + table_name + " " \
                    "WHERE consentRecordId LIKE %s AND id > %s;"

        arguments = (
            '%' + str(cr_id) + '%',
            int(csr_primary_key),
        )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data)
        logger.info("Got data_list: " + repr(data_list))

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i][-1])

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))
        return cursor, id_list


def get_last_csr_id(cursor=None, consent_id=None, account_id="", table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

    try:
        consent_id = str(consent_id)
    except Exception:
        raise TypeError("consent_id MUST be str, not " + str(type(consent_id)))
    try:
        account_id = int(account_id)
    except Exception:
        logger.warning("account_id SHOULD be int, not " + str(type(account_id)))
        logger.warning("Querying without Account ID")

        sql_query = "SELECT consentStatusRecordId " \
                    "FROM " + table_name + " " \
                    "WHERE consentRecordId LIKE %s " \
                    "ORDER BY id DESC " \
                    "LIMIT 1;"

        arguments = (
            '%' + str(consent_id) + '%',
        )

    else:
        logger.debug("Querying with account_id")
        sql_query = "SELECT consentStatusRecordId " \
                    "FROM " + table_name + " " \
                    "WHERE consentRecordId LIKE %s " \
                    "AND Accounts_id = %s " \
                    "ORDER BY id DESC " \
                    "LIMIT 1;"

        arguments = (
            '%' + str(consent_id) + '%',
            int(account_id),
        )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        entry_id = str(data_list[0])
        logger.info("Got entry_id: " + repr(entry_id))

        return cursor, entry_id


def get_account_id_by_csr_id(cursor=None, cr_id=None, acc_table_name=None, slr_table_name=None, cr_table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if acc_table_name is None:
        raise AttributeError("Provide acc_table_name as parameter")
    if slr_table_name is None:
        raise AttributeError("Provide slr_table_name as parameter")
    if cr_table_name is None:
        raise AttributeError("Provide cr_table_name as parameter")


    sql_query = "SELECT `Accounts`.`id` " \
                "FROM " + acc_table_name + " " \
                "INNER JOIN " + slr_table_name + " on " + acc_table_name + ".`id` = " + slr_table_name + ".`Accounts_id` " \
                "INNER JOIN " + cr_table_name + " on " + slr_table_name + ".`id` = " + cr_table_name + ".`ServiceLinkRecords_id` " \
                "WHERE " + cr_table_name + ".`consentRecordId` LIKE %s " \
                "LIMIT 1;"

    arguments = (
        '%' + str(cr_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data[0])
        logger.info("Got data_list: " + repr(data_list))

        entry_id = str(data_list[0])
        logger.info("Got entry_id: " + repr(entry_id))

        return cursor, entry_id


def get_consent_ids(cursor=None, surrogate_id="", slr_id="", subject_id="", consent_pair_id="", account_id="", table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

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

    sql_query = "SELECT consentRecordId " \
                "FROM " + table_name + " " \
                "WHERE surrogateId LIKE %s " \
                "AND serviceLinkRecordId LIKE %s " \
                "AND subjectId LIKE %s " \
                "AND consentPairId LIKE %s " \
                "AND Accounts_id LIKE %s;"

    arguments = (
        '%' + str(surrogate_id) + '%',
        '%' + str(slr_id) + '%',
        '%' + str(subject_id) + '%',
        '%' + str(consent_pair_id) + '%',
        '%' + str(account_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))
        #logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data)
        logger.info("Got data_list: " + repr(data_list))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i][0])
        logger.info("Formatted data_list: " + repr(data_list))

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_last_consent_id(cursor=None, surrogate_id="", slr_id="", subject_id="", consent_pair_id="", account_id="", table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")

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

    sql_query = "SELECT consentRecordId " \
                "FROM " + table_name + " " \
                "WHERE surrogateId LIKE %s " \
                "AND serviceLinkRecordId LIKE %s " \
                "AND subjectId LIKE %s " \
                "AND consentPairId LIKE %s " \
                "AND Accounts_id LIKE %s " \
                "ORDER BY id DESC LIMIT 1;"

    arguments = (
        '%' + str(surrogate_id) + '%',
        '%' + str(slr_id) + '%',
        '%' + str(subject_id) + '%',
        '%' + str(consent_pair_id) + '%',
        '%' + str(account_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))
        #logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data)
        logger.info("Got data_list: " + repr(data_list))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i][0])
        logger.info("Formatted data_list: " + repr(data_list))

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_consent_status_ids(cursor=None, cr_id="", account_id="", primary_key_filter=0, table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")
    try:
        cr_id = str(cr_id)
    except Exception:
        raise TypeError("cr_id MUST be str, not " + str(type(cr_id)))
    try:
        account_id = str(account_id)
    except Exception:
        raise TypeError("account_id MUST be str, not " + str(type(account_id)))
    try:
        primary_key_filter = int(primary_key_filter)
    except Exception:
        raise TypeError("primary_key_filter MUST be int, not " + str(type(primary_key_filter)))

    sql_query = "SELECT consentStatusRecordId " \
                "FROM " + table_name + " " \
                "WHERE consentRecordId LIKE %s " \
                "AND Accounts_id LIKE %s" \
                " AND id > %s;"

    arguments = (
        '%' + str(cr_id) + '%',
        '%' + str(account_id) + '%',
        int(primary_key_filter),
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))
        #logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data)
        logger.info("Got data_list: " + repr(data_list))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i][0])
        logger.info("Formatted data_list: " + repr(data_list))

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))

        return cursor, id_list


def get_consent_status_id_filter(cursor=None, csr_id="", account_id="", table_name=None):
    logger.info("Executing")
    if cursor is None:
        raise AttributeError("Provide cursor as parameter")
    if table_name is None:
        raise AttributeError("Provide table_name as parameter")
    try:
        csr_id = str(csr_id)
    except Exception:
        raise TypeError("csr_id MUST be str, not " + str(type(csr_id)))
    try:
        account_id = str(account_id)
    except Exception:
        raise TypeError("account_id MUST be str, not " + str(type(account_id)))

    sql_query = "SELECT id " \
                "FROM " + table_name + " " \
                "WHERE consentStatusRecordId LIKE %s " \
                "AND Accounts_id LIKE %s;"

    arguments = (
        '%' + str(csr_id) + '%',
        '%' + str(account_id) + '%',
    )

    try:
        cursor, data = execute_sql_select_2(cursor=cursor, sql_query=sql_query, arguments=arguments)
    except Exception as exp:
        logger.debug('sql_query: ' + repr(exp))
        raise
    else:
        logger.debug("Got data: " + repr(data))
        #logger.debug("Got data[0]: " + repr(data[0]))
        data_list = list(data)
        logger.info("Got data_list: " + repr(data_list))

        if len(data) == 0:
            logger.error("IndexError('DB query returned no results')")
            raise IndexError("DB query returned no results")

        for i in range(len(data_list)):
            data_list[i] = str(data_list[i][0])
        logger.info("Formatted data_list: " + repr(data_list))

        id_list = data_list
        logger.info("Got id_list: " + repr(id_list))
        id = max(id_list)
        logger.info("Got max id: " + str(id))

        return cursor, id




