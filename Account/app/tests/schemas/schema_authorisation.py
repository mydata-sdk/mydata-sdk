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

schema_give_consent = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "properties": {
        "sink": {
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
            "consent_status_record": {
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
            "consent_status_record",
            "consent_record"
          ],
          "type": "object"
        },
        "source": {
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
            "consent_status_record": {
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
            "consent_status_record",
            "consent_record"
          ],
          "type": "object"
        }
      },
      "required": [
        "source",
        "sink"
      ],
      "type": "object"
    }
  },
  "required": [
    "data"
  ],
  "type": "object"
}


schema_consent_status_change = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
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
    "data"
  ],
  "type": "object"
}


schema_consent_listing = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "items": {
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
      "type": "array"
    }
  },
  "required": [
    "data"
  ],
  "type": "object"
}


schema_consent_status_listing = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "items": {
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
      "type": "array"
    }
  },
  "required": [
    "data"
  ],
  "type": "object"
}

schema_consent_status = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
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
    "data"
  ],
  "type": "object"
}

