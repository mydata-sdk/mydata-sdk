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
  "type": "object",
  "properties": {
    "meta": {
      "type": "object",
      "properties": {
        "activationInstructions": {
          "type": "string"
        }
      },
      "required": [
        "activationInstructions"
      ]
    },
    "data": {
      "type": "object",
      "properties": {
        "attributes": {
          "type": "object",
          "properties": {
            "username": {
              "type": "string"
            },
            "firstName": {
              "type": "string"
            },
            "lastName": {
              "type": "string"
            },
            "dateOfBirth": {
              "type": "string"
            },
            "acceptTermsOfService": {
              "type": "boolean"
            },
            "password": {
              "type": "string"
            },
            "email": {
              "type": "string"
            }
          },
          "required": [
            "username",
            "firstName",
            "lastName",
            "dateOfBirth",
            "acceptTermsOfService",
            "password",
            "email"
          ]
        },
        "type": {
          "type": "string"
        },
        "id": {
          "type": "string"
        }
      },
      "required": [
        "attributes",
        "type",
        "id"
      ]
    }
  },
  "required": [
    "meta",
    "data"
  ]
}

schema_account_create_password_length = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "errors": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "default": "400"
        },
        "detail": {
          "type": "object",
          "properties": {
            "data": {
              "type": "object",
              "properties": {
                "attributes": {
                  "type": "object",
                  "properties": {
                    "password": {
                      "type": "array",
                      "items": {
                        "type": "string",
                        "default": "Length must be between 4 and 20."
                      }
                    }
                  },
                  "required": [
                    "password"
                  ]
                }
              },
              "required": [
                "attributes"
              ]
            }
          },
          "required": [
            "data"
          ]
        },
        "source": {
          "type": "string",
          "default": "/api/accounts/"
        },
        "status": {
          "type": "string",
          "default": "Bad Request, Bad request syntax or unsupported method"
        },
        "title": {
          "type": "string",
          "default": "Invalid payload"
        }
      },
      "required": [
        "code",
        "detail",
        "source",
        "status",
        "title"
      ]
    }
  },
  "required": [
    "errors"
  ]
}


schema_account_create_username_length = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "errors": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "default": "400"
        },
        "detail": {
          "type": "object",
          "properties": {
            "data": {
              "type": "object",
              "properties": {
                "attributes": {
                  "type": "object",
                  "properties": {
                    "username": {
                      "type": "array",
                      "items": {
                        "type": "string",
                        "default": "Length must be between 3 and 255."
                      }
                    }
                  },
                  "required": [
                    "username"
                  ]
                }
              },
              "required": [
                "attributes"
              ]
            }
          },
          "required": [
            "data"
          ]
        },
        "source": {
          "type": "string",
          "default": "/api/accounts/"
        },
        "status": {
          "type": "string",
          "default": "Bad Request, Bad request syntax or unsupported method"
        },
        "title": {
          "type": "string",
          "default": "Invalid payload"
        }
      },
      "required": [
        "code",
        "detail",
        "source",
        "status",
        "title"
      ]
    }
  },
  "required": [
    "errors"
  ]
}


schema_account_create_email_length = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "errors": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "default": "400"
        },
        "detail": {
          "type": "object",
          "properties": {
            "data": {
              "type": "object",
              "properties": {
                "attributes": {
                  "type": "object",
                  "properties": {
                    "email": {
                      "type": "array",
                      "items": {
                        "type": "string",
                        "default": "Length must be between 3 and 255."
                      }
                    }
                  },
                  "required": [
                    "email"
                  ]
                }
              },
              "required": [
                "attributes"
              ]
            }
          },
          "required": [
            "data"
          ]
        },
        "source": {
          "type": "string",
          "default": "/api/accounts/"
        },
        "status": {
          "type": "string",
          "default": "Bad Request, Bad request syntax or unsupported method"
        },
        "title": {
          "type": "string",
          "default": "Invalid payload"
        }
      },
      "required": [
        "code",
        "detail",
        "source",
        "status",
        "title"
      ]
    }
  },
  "required": [
    "errors"
  ]
}

schema_account_create_email_invalid = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "errors": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "default": "400"
        },
        "detail": {
          "type": "object",
          "properties": {
            "data": {
              "type": "object",
              "properties": {
                "attributes": {
                  "type": "object",
                  "properties": {
                    "email": {
                      "type": "array",
                      "items": {
                        "type": "string",
                        "default": "Not a valid email address."
                      }
                    }
                  },
                  "required": [
                    "email"
                  ]
                }
              },
              "required": [
                "attributes"
              ]
            }
          },
          "required": [
            "data"
          ]
        },
        "source": {
          "type": "string",
          "default": "/api/accounts/"
        },
        "status": {
          "type": "string",
          "default": "Bad Request, Bad request syntax or unsupported method"
        },
        "title": {
          "type": "string",
          "default": "Invalid payload"
        }
      },
      "required": [
        "code",
        "detail",
        "source",
        "status",
        "title"
      ]
    }
  },
  "required": [
    "errors"
  ]
}


schema_account_create_firstname_length = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "errors": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "default": "400"
        },
        "detail": {
          "type": "object",
          "properties": {
            "data": {
              "type": "object",
              "properties": {
                "attributes": {
                  "type": "object",
                  "properties": {
                    "firstName": {
                      "type": "array",
                      "items": {
                        "type": "string",
                        "default": "Length must be between 3 and 255."
                      }
                    }
                  },
                  "required": [
                    "firstName"
                  ]
                }
              },
              "required": [
                "attributes"
              ]
            }
          },
          "required": [
            "data"
          ]
        },
        "source": {
          "type": "string",
          "default": "/api/accounts/"
        },
        "status": {
          "type": "string",
          "default": "Bad Request, Bad request syntax or unsupported method"
        },
        "title": {
          "type": "string",
          "default": "Invalid payload"
        }
      },
      "required": [
        "code",
        "detail",
        "source",
        "status",
        "title"
      ]
    }
  },
  "required": [
    "errors"
  ]
}


schema_account_create_lastname_length = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "errors": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "default": "400"
        },
        "detail": {
          "type": "object",
          "properties": {
            "data": {
              "type": "object",
              "properties": {
                "attributes": {
                  "type": "object",
                  "properties": {
                    "lastName": {
                      "type": "array",
                      "items": {
                        "type": "string",
                        "default": "Length must be between 3 and 255."
                      }
                    }
                  },
                  "required": [
                    "lastName"
                  ]
                }
              },
              "required": [
                "attributes"
              ]
            }
          },
          "required": [
            "data"
          ]
        },
        "source": {
          "type": "string",
          "default": "/api/accounts/"
        },
        "status": {
          "type": "string",
          "default": "Bad Request, Bad request syntax or unsupported method"
        },
        "title": {
          "type": "string",
          "default": "Invalid payload"
        }
      },
      "required": [
        "code",
        "detail",
        "source",
        "status",
        "title"
      ]
    }
  },
  "required": [
    "errors"
  ]
}


schema_account_create_date_invalid = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "errors": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "default": "400"
        },
        "detail": {
          "type": "object",
          "properties": {
            "data": {
              "type": "object",
              "properties": {
                "attributes": {
                  "type": "object",
                  "properties": {
                    "dateOfBirth": {
                      "type": "array",
                      "items": {
                        "type": "string",
                        "default": "Not a valid date."
                      }
                    }
                  },
                  "required": [
                    "dateOfBirth"
                  ]
                }
              },
              "required": [
                "attributes"
              ]
            }
          },
          "required": [
            "data"
          ]
        },
        "source": {
          "type": "string",
          "default": "/api/accounts/"
        },
        "status": {
          "type": "string",
          "default": "Bad Request, Bad request syntax or unsupported method"
        },
        "title": {
          "type": "string",
          "default": "Invalid payload"
        }
      },
      "required": [
        "code",
        "detail",
        "source",
        "status",
        "title"
      ]
    }
  },
  "required": [
    "errors"
  ]
}


schema_account_create_tos = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "errors": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "default": "400"
        },
        "detail": {
          "type": "object",
          "properties": {
            "data": {
              "type": "object",
              "properties": {
                "attributes": {
                  "type": "object",
                  "properties": {
                    "acceptTermsOfService": {
                      "type": "array",
                      "items": {
                        "type": "string",
                        "default": "Must be equal to True."
                      }
                    }
                  },
                  "required": [
                    "acceptTermsOfService"
                  ]
                }
              },
              "required": [
                "attributes"
              ]
            }
          },
          "required": [
            "data"
          ]
        },
        "source": {
          "type": "string",
          "default": "/api/accounts/"
        },
        "status": {
          "type": "string",
          "default": "Bad Request, Bad request syntax or unsupported method"
        },
        "title": {
          "type": "string",
          "default": "Invalid payload"
        }
      },
      "required": [
        "code",
        "detail",
        "source",
        "status",
        "title"
      ]
    }
  },
  "required": [
    "errors"
  ]
}


