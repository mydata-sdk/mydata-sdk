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

schema_db_clear = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "Account": {
      "type": "string",
      "default": "MySQL Database cleared"
    },
    "ApiKey": {
      "type": "string",
      "default": "ApiKey Database cleared"
    },
    "Blackbox": {
      "type": "string",
      "default": "Blackbox Database cleared"
    }
  },
  "required": [
    "Account",
    "ApiKey",
    "Blackbox"
  ]
}

system_running = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "status": {
      "type": "string",
      "default": "running"
    }
  },
  "required": [
    "status"
  ]
}

schema_system_status = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "attributes": {
      "properties": {
        "db_row_counts": {
          "properties": {
            "account": {
              "type": "integer"
            },
            "consent": {
              "type": "integer"
            },
            "consent_status": {
              "type": "integer"
            },
            "service_link": {
              "type": "integer"
            },
            "service_link_status": {
              "type": "integer"
            }
          },
          "required": [
            "service_link",
            "consent",
            "account",
            "consent_status",
            "service_link_status"
          ],
          "type": "object"
        },
        "title": {
          "type": "string"
        }
      },
      "required": [
        "db_row_counts",
        "title"
      ],
      "type": "object"
    },
    "type": {
      "type": "string"
    }
  },
  "required": [
    "attributes",
    "type"
  ],
  "type": "object"
}

schema_sdk_auth = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "properties": {
        "Api-Key-Sdk": {
            "type": "string"
        }
    },
    "required": [
        "Api-Key-Sdk",
    ],
    "type": "object"
}