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

schema_slr_init = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "properties": {
        "code": {
            "type": "string"
        },
        "data": {
            "properties": {
                "attributes": {
                    "properties": {
                        "slr_id": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "slr_id"
                    ],
                    "type": "object"
                }
            },
            "required": [
                "attributes"
            ],
            "type": "object"
        }
    },
    "required": [
        "code",
        "data"
    ],
    "type": "object"
}

schema_slr_sign = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "id": "http://example.com/example.json",
    "properties": {
        "code": {
            "type": "string"
        },
        "data": {
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
        }
    },
    "required": [
        "code",
        "data"
    ],
    "type": "object"
}
