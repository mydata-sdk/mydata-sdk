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
