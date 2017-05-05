# -*- coding: utf-8 -*-

"""
Minimum viable account

__author__ = "Jani Yli-Kantola"
__copyright__ = "Digital Health Revolution (c) 2016"
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
__date__ = 26.5.2016
"""
import inspect


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


class ApiKeyNotFoundError(StandardError):
    """
    Exception to indicate that there were no key for user account in database.

     https://docs.python.org/2/tutorial/errors.html#user-defined-exceptions
    """
    pass


class AccountIdNotFoundError(StandardError):
    """
    Exception to indicate that provided Api Key was not found.

     https://docs.python.org/2/tutorial/errors.html#user-defined-exceptions
    """
    pass


def get_current_line_no():
    """
    Returns the current line number program.
    :return: Line number
    """
    return inspect.currentframe().f_back.f_lineno
