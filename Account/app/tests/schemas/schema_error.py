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

schema_request_error_detail_as_str = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "properties": {
        "errors": {
            "properties": {
                "code": {
                    "type": "string"
                },
                "detail": {
                    "type": "string"
                },
                "source": {
                    "type": "string"
                },
                "status": {
                    "type": "string"
                },
                "title": {
                    "type": "string"
                }
            },
            "required": [
                "status",
                "source",
                "code",
                "detail",
                "title"
            ],
            "type": "object"
        }
    },
    "required": [
        "errors"
    ],
    "type": "object"
}


schema_request_error_detail_as_dict = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "properties": {
        "errors": {
            "properties": {
                "code": {
                    "type": "string"
                },
                "detail": {
                    "properties": {},
                    "type": "object"
                },
                "source": {
                    "type": "string"
                },
                "status": {
                    "type": "string"
                },
                "title": {
                    "type": "string"
                }
            },
            "required": [
                "status",
                "source",
                "code",
                "detail",
                "title"
            ],
            "type": "object"
        }
    },
    "required": [
        "errors"
    ],
    "type": "object"
}
