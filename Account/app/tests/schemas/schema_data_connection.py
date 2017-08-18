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

schema_authorisation_token_data = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "properties": {
        "consent_record": {
          "properties": {
            "attributes": {
              "properties": {
                "header": {
                  "properties": {
                    "kid": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "kid"
                  ],
                  "type": "object"
                },
                "payload": {
                  "type": "string"
                },
                "protected": {
                  "type": "string"
                },
                "signature": {
                  "type": "string"
                }
              },
              "required": [
                "header",
                "protected",
                "payload",
                "signature"
              ],
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
        },
        "service_link_record": {
          "properties": {
            "attributes": {
              "properties": {
                "payload": {
                  "type": "string"
                },
                "signatures": {
                  "items": {
                    "properties": {
                      "header": {
                        "properties": {
                          "kid": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "kid"
                        ],
                        "type": "object"
                      },
                      "protected": {
                        "type": "string"
                      },
                      "signature": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "header",
                      "protected",
                      "signature"
                    ],
                    "type": "object"
                  },
                  "type": "array"
                }
              },
              "required": [
                "signatures",
                "payload"
              ],
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
        "service_link_record",
        "consent_record"
      ],
      "type": "object"
    }
  },
  "required": [
    "data"
  ],
  "type": "object"
}

