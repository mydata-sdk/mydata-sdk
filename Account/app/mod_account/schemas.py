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

schema_account_new = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "properties": {
        "attributes": {
          "properties": {
            "firstname": {
              "maxLength": 250,
              "minLength": 3,
              "pattern": "[a-zA-Z]+",
              "type": "string"
            },
            "lastname": {
              "maxLength": 250,
              "minLength": 3,
              "pattern": "[a-zA-Z]+",
              "type": "string"
            },
            "password": {
              "maxLength": 20,
              "minLength": 4,
              "pattern": "[a-zA-Z0-9!#¤%&/()=?+_-]+",
              "type": "string"
            },
            "username": {
              "maxLength": 250,
              "minLength": 3,
              "pattern": "[a-zA-Z0-9!#¤%&/()=?+_-]+",
              "type": "string"
            }
          },
          "required": [
            "username",
            "lastname",
            "password",
            "firstname"
          ],
          "type": "object"
        },
        "type": {
          "maxLength": 250,
          "minLength": 3,
          "pattern": "[a-zA-Z0-9!#¤%&/()=?+_-]+",
          "type": "string"
        }
      },
      "required": [
        "attributes",
        "type"
      ],
      "type": "object"
    }
  },
  "required": [
    "data"
  ],
  "type": "object"
}


schema_account_info = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "properties": {
        "attributes": {
          "properties": {
            "avatar": {
              "type": "string"
            },
            "firstname": {
              "type": "string"
            },
            "lastname": {
              "type": "string"
            }
          },
          "type": "object"
        },
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      },
      "required": [
        "attributes",
        "type",
        "id"
      ],
      "type": "object"
    }
  },
  "required": [
    "data"
  ],
  "type": "object"
}

