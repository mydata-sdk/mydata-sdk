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
