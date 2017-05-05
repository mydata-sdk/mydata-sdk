# -*- coding: utf-8 -*-

"""
Minimum viable Key management. NOT FOR PRODUCTION USE.


__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""
import inspect
import json
import logging
from logging.handlers import TimedRotatingFileHandler
from os.path import isdir, dirname, abspath
from os import mkdir


def append_description_to_exception(exp=None, description=None):
    """
    Adds additional description to Exception. As result original Exception can be reraised with additional information
    http://stackoverflow.com/questions/9157210/how-do-i-raise-the-same-exception-with-a-custom-message-in-python

    :param exp: Exception
    :param description: Description to add as String
    :return: Exception
    """
    if exp is None:
        raise AttributeError("Provide exp as parameter")
    if description is None:
        raise AttributeError("Provide description as parameter")

    if not exp.args:
        exp.args = ('',)

    try:
        description = str(description)
    except Exception:
        try:
            description = repr(description)
        except Exception:
            description = 'Description could not be converted to string'

    exp.args = exp.args + (description,)
    return exp


class KeyNotFoundError(StandardError):
    """
    Exception to indicate that there were no key for user account in database.

     https://docs.python.org/2/tutorial/errors.html#user-defined-exceptions
    """
    pass


def jws_header_fix(malformed_jws_json=None):
    """
    Fixes malformed header object after jws.serialize().
    For some reason serialization messes up "header" from "header": {} to "header": "{}"

    Function does not check if header field in given dictionary is malformed, it's expecting it to be.

    :param malformed_jws_json: JSON presentation of JWS with malformed header field
    :return: JSON presentation of JWS fixed header field.
    """
    try:
        fixed_jws_json = malformed_jws_json.replace('"{', '{').replace('}"', '}').replace('\\"', '"')
    except Exception as exp:
        exp = append_description_to_exception(exp=exp, description='Could not fix header in JWS json')
        raise
    else:
        return fixed_jws_json


def get_current_line_no():
    """
    Returns the current line number program.
    :return: Line number
    """
    return inspect.currentframe().f_back.f_lineno
