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


schema_account_sdk_info = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "properties": {
    "data": {
      "properties": {
        "attributes": {
          "type": "object"
        },
        "id": {
          "type": "string"
        },
        "type": {
          "enum": [
            "Account"
          ],
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


schema_account_get = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "properties": {
    "data": {
      "properties": {
        "attributes": {
          "properties": {
            "activated": {
              "type": "integer"
            }
          },
          "required": [
            "activated"
          ],
          "type": "object"
        },
        "id": {
          "type": "string"
        },
        "type": {
          "enum": [
            "Account"
          ],
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

schema_account_auth = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "properties": {
        "Api-Key-User": {
            "type": "string"
        },
        "account_id": {
            "type": "string"
        }
    },
    "required": [
        "Api-Key-User",
        "account_id"
    ],
    "type": "object"
}

schema_account_create = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "properties": {
        "attributes": {
          "properties": {
            "activated": {
              "type": "integer"
            }
          },
          "required": [
            "activated"
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
    "data"
  ],
  "type": "object"
}


schema_account_info_listing = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "items": {
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
            "required": [
              "lastname",
              "avatar",
              "firstname"
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
      "type": "array"
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
          "required": [
            "lastname",
            "avatar",
            "firstname"
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
    "data"
  ],
  "type": "object"
}

schema_account_event_log_listing = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "items": {
        "properties": {
          "attributes": {
            "properties": {
              "action": {
                "type": "string"
              },
              "actor": {
                "type": "string"
              },
              "resource": {
                "type": "string"
              },
              "timestamp": {
                "type": "string"
              }
            },
            "required": [
              "action",
              "timestamp",
              "resource",
              "actor"
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
      "type": "array"
    }
  },
  "required": [
    "data"
  ],
  "type": "object"
}