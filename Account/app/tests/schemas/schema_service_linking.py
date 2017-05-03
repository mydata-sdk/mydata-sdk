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


schema_slr_store_sink = {
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
                "operator_id": {
                  "type": "string"
                },
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
                "service_id": {
                  "type": "string"
                },
                "service_link_record": {
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
                "service_link_record_id": {
                  "type": "string"
                },
                "surrogate_id": {
                  "type": "string"
                }
              },
              "required": [
                "operator_id",
                "surrogate_id",
                "service_link_record",
                "service_id",
                "pop_key",
                "service_link_record_id"
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
                "issued_at": {
                  "type": "integer"
                },
                "prev_record_id": {
                  "type": "string"
                },
                "service_link_record_id": {
                  "type": "string"
                },
                "service_link_status_record": {
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
                "service_link_status_record_id": {
                  "type": "string"
                },
                "status": {
                  "type": "string"
                }
              },
              "required": [
                "service_link_status_record_id",
                "status",
                "service_link_status_record",
                "issued_at",
                "prev_record_id",
                "service_link_record_id"
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

schema_slr_store_source = {
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
                "operator_id": {
                  "type": "string"
                },
                "service_id": {
                  "type": "string"
                },
                "service_link_record": {
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
                "service_link_record_id": {
                  "type": "string"
                },
                "surrogate_id": {
                  "type": "string"
                }
              },
              "required": [
                "operator_id",
                "surrogate_id",
                "service_link_record",
                "service_id",
                "service_link_record_id"
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
                "issued_at": {
                  "type": "integer"
                },
                "prev_record_id": {
                  "type": "string"
                },
                "service_link_record_id": {
                  "type": "string"
                },
                "service_link_status_record": {
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
                "service_link_status_record_id": {
                  "type": "string"
                },
                "status": {
                  "type": "string"
                }
              },
              "required": [
                "service_link_status_record_id",
                "status",
                "service_link_status_record",
                "issued_at",
                "prev_record_id",
                "service_link_record_id"
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
