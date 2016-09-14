# -*- coding: utf-8 -*-

"""
__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

# Import dependencies
from marshmallow import Schema, fields, validates, ValidationError
from marshmallow.validate import Range, Regexp, ContainsOnly, Equal, OneOf, Length

TYPE_LIST = ["Personal", "Work", "School", "Other"]  # List that contains types for contact details

STRING_MIN_LENGTH = 3
STRING_MAX_LENGTH = 255

PWD_MIN_LENGTH = 4
PWD_MAX_LENGTH = 20

GENERAL_STRING_MIN_LENGTH = 3
GENERAL_STRING_MAX_LENGTH = 100
GENERAL_REGEX = "[a-zA-Z]+"

USERNAME_MIN = GENERAL_STRING_MIN_LENGTH
USERNAME_MAX = GENERAL_STRING_MAX_LENGTH
USERNAME_REGEX = "[a-zA-Z0-9!#¤%&/()=?+_-]+"

PASSWORD_MIN = GENERAL_STRING_MIN_LENGTH
PASSWORD_MAX = GENERAL_STRING_MAX_LENGTH
PASSWORD_REGEX = "[a-zA-Z0-9!#¤%&/()=?+_-]+"

FIRSTNAME_MIN = GENERAL_STRING_MIN_LENGTH
FIRSTNAME_MAX = GENERAL_STRING_MAX_LENGTH
FIRSTNAME_REGEX = GENERAL_REGEX

LASTNAME_MIN = GENERAL_STRING_MIN_LENGTH
LASTNAME_MAX = GENERAL_STRING_MAX_LENGTH
LASTNAME_REGEX = GENERAL_REGEX

class BaseSchema(Schema):
    type = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))


class AccountSchema(BaseSchema):
    username = fields.Str(required=True,
                          validate=[
                              Range(
                                  min=USERNAME_MIN, max=USERNAME_MAX,
                                  error='Got: {input} as input, should be between {min} - {max}.'
                              ),
                              Regexp(regex=USERNAME_REGEX, error="'{input}' not matching to '{regex}'")
                          ])

    password = fields.Str(required=True,
                          validate=[
                              Range(
                                  min=USERNAME_MIN, max=USERNAME_MAX,
                                  error='Got: {input} as input, should be between {min} - {max}.'
                              ),
                              Regexp(regex=PASSWORD_REGEX, error="'{input}' not matching to '{regex}'")
                          ])

    firstName = fields.Str(required=True,
                           validate=[
                               Range(
                                   min=FIRSTNAME_MIN, max=FIRSTNAME_MAX,
                                   error='Got: {input} as input, should be between {min} - {max}.'
                               ),
                               Regexp(regex=FIRSTNAME_REGEX, error="'{input}' not matching to '{regex}'")
                           ])

    lastName = fields.Str(required=True,
                          validate=[
                              Range(
                                  min=LASTNAME_MIN, max=LASTNAME_MAX,
                                  error='Got: {input} as input, should be between {min} - {max}.'
                               ),
                              Regexp(regex=LASTNAME_REGEX, error="'{input}' not matching to '{regex}'")
                          ])

    email = fields.Email(required=True, error='Email not valid')
    dateOfBirth = fields.Date(required=True, error='Not valid date. Provide ISO8601-formatted date string.')
    acceptTermsOfService = fields.Bool(required=True, validate=[ContainsOnly(choices='True')])


##
##
# Account creation
class AccountAttributes(Schema):
    username = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    password = fields.Str(validate=Length(min=PWD_MIN_LENGTH, max=PWD_MAX_LENGTH))
    firstName = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    lastName = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    email = fields.Email(required=True, validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    dateOfBirth = fields.Date(required=True, error='Not valid date. Provide ISO8601-formatted date string.')
    acceptTermsOfService = fields.Str(required=True, validate=Equal("True"))


class AccountData(Schema):
    type = fields.Str(required=True, validate=Equal("Account"))
    id = fields.Str(validate=Length(max=STRING_MAX_LENGTH))
    attributes = fields.Nested(nested=AccountAttributes, required=True)


class AccountSchema2(Schema):
    data = fields.Nested(nested=AccountData, required=True)


##
##
# particulars
class ParticularsAttributes(Schema):
    firstName = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    lastName = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    img = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    dateOfBirth = fields.Date(error='Not valid date. Provide ISO8601-formatted date string.')


class ParticularsData(Schema):
    type = fields.Str(required=True, validate=Equal("Particular"))
    id = fields.Str(validate=Length(max=STRING_MAX_LENGTH))
    attributes = fields.Nested(nested=ParticularsAttributes, required=True)


class ParticularsSchema(Schema):
    data = fields.Nested(nested=ParticularsData, required=True)


##
##
# Contacts
class ContactsAttributes(Schema):
    address1 = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    address2 = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    postalCode = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    city = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    state = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    country = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    type = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    primary = fields.Str(validate=OneOf(["True", "False"]))


class ContactsData(Schema):
    type = fields.Str(required=True, validate=Equal("Contact"))
    id = fields.Str(validate=Length(max=STRING_MAX_LENGTH))
    attributes = fields.Nested(nested=ContactsAttributes, required=True)


class ContactsSchema(Schema):
    data = fields.Nested(nested=ContactsData, required=True)


##
##
# Telephone
class TelephonesAttributes(Schema):
    tel = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    type = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    primary = fields.Str(validate=OneOf(TYPE_LIST))


class TelephonesData(Schema):
    type = fields.Str(required=True, validate=Equal("Telephone"))
    id = fields.Str(validate=Length(max=STRING_MAX_LENGTH))
    attributes = fields.Nested(nested=TelephonesAttributes, required=True)


class TelephonesSchema(Schema):
    data = fields.Nested(nested=TelephonesData, required=True)


##
##
# Email
class EmailsAttributes(Schema):
    email = fields.Email(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    type = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    primary = fields.Str(validate=OneOf(TYPE_LIST))


class EmailsData(Schema):
    type = fields.Str(required=True, validate=Equal("Email"))
    id = fields.Str(validate=Length(max=STRING_MAX_LENGTH))
    attributes = fields.Nested(nested=EmailsAttributes, required=True)


class EmailsSchema(Schema):
    data = fields.Nested(nested=EmailsData, required=True)


##
##
# Email
class SettingsAttributes(Schema):
    key = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))
    value = fields.Str(validate=Length(min=STRING_MIN_LENGTH, max=STRING_MAX_LENGTH))


class SettingsData(Schema):
    type = fields.Str(required=True, validate=Equal("Setting"))
    id = fields.Str(validate=Length(max=STRING_MAX_LENGTH))
    attributes = fields.Nested(nested=SettingsAttributes, required=True)


class SettingsSchema(Schema):
    data = fields.Nested(nested=SettingsData, required=True)
