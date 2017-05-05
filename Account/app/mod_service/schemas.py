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

schema_sl_init_sink = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "properties": {
        "code": {
            "type": "string"
        },
        "data": {
            "properties": {
                "attributes": {
                    "properties": {
                        "pop_key": {
                            "properties": {
                                "crv": {
                                    "type": "string"
                                },
                                "cvr": {
                                    "type": "string"
                                },
                                "d": {
                                    "type": "string"
                                },
                                "kid": {
                                    "type": "string"
                                },
                                "kty": {
                                    "type": "string"
                                },
                                "x": {
                                    "type": "string"
                                },
                                "y": {
                                    "type": "string"
                                }
                            },
                            "required": [
                                "crv",
                                "d",
                                "cvr",
                                "y",
                                "x",
                                "kid",
                                "kty"
                            ],
                            "type": "object"
                        },
                        "slr_id": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "slr_id",
                        "pop_key"
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

schema_sl_init_source = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
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

schema_sl_sign = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "properties": {
        "code": {
            "type": "string"
        },
        "data": {
            "properties": {
                "attributes": {
                    "properties": {
                        "iat": {
                            "type": "integer"
                        },
                        "link_id": {
                            "type": "string"
                        },
                        "operator_id": {
                            "type": "string"
                        },
                        "operator_key": {
                            "properties": {
                                "crv": {
                                    "type": "string"
                                },
                                "cvr": {
                                    "type": "string"
                                },
                                "d": {
                                    "type": "string"
                                },
                                "kid": {
                                    "type": "string"
                                },
                                "kty": {
                                    "type": "string"
                                },
                                "x": {
                                    "type": "string"
                                },
                                "y": {
                                    "type": "string"
                                }
                            },
                            "required": [
                                "crv",
                                "d",
                                "cvr",
                                "y",
                                "x",
                                "kid",
                                "kty"
                            ],
                            "type": "object"
                        },
                        "service_id": {
                            "type": "string"
                        },
                        "surrogate_id": {
                            "type": "string"
                        },
                        "version": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "operator_id",
                        "surrogate_id",
                        "link_id",
                        "operator_key",
                        "version",
                        "iat",
                        "service_id"
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
    },
    "required": [
        "code",
        "data"
    ],
    "type": "object"
}


schema_sl_store = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "code": {
      "type": "string"
    },
    "data": {
      "properties": {
        "slr": {
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
        },
        "ssr": {
          "properties": {
            "attributes": {
              "properties": {
                "iat": {
                  "type": "integer"
                },
                "prev_record_id": {
                  "type": "string"
                },
                "record_id": {
                  "type": "string"
                },
                "sl_status": {
                  "type": "string"
                },
                "slr_id": {
                  "type": "string"
                },
                "surrogate_id": {
                  "type": "string"
                },
                "version": {
                  "type": "string"
                }
              },
              "required": [
                "slr_id",
                "surrogate_id",
                "sl_status",
                "version",
                "record_id",
                "iat",
                "prev_record_id"
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
      },
      "required": [
        "slr",
        "ssr"
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