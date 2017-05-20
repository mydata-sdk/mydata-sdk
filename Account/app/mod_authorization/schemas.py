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

schema_consent_new = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "properties": {
        "sink": {
          "properties": {
            "consent_record_payload": {
              "properties": {
                "attributes": {
                  "properties": {
                    "common_part": {
                      "properties": {
                        "cr_id": {
                          "type": "string"
                        },
                        "exp": {
                          "type": "integer"
                        },
                        "iat": {
                          "type": "integer"
                        },
                        "nbf": {
                          "type": "integer"
                        },
                        "operator": {
                          "type": "string"
                        },
                        "role": {
                          "type": "string"
                        },
                        "rs_description": {
                          "properties": {
                            "resource_set": {
                              "properties": {
                                "dataset": {
                                  "items": {
                                    "properties": {
                                      "dataset_id": {
                                        "type": "string"
                                      },
                                      "distribution_id": {
                                        "type": "string"
                                      },
                                      "distribution_url": {
                                        "type": "string"
                                      }
                                    },
                                    "required": [
                                      "distribution_url",
                                      "distribution_id",
                                      "dataset_id"
                                    ],
                                    "type": "object"
                                  },
                                  "type": "array"
                                },
                                "rs_id": {
                                  "type": "string"
                                }
                              },
                              "required": [
                                "rs_id",
                                "dataset"
                              ],
                              "type": "object"
                            }
                          },
                          "required": [
                            "resource_set"
                          ],
                          "type": "object"
                        },
                        "slr_id": {
                          "type": "string"
                        },
                        "subject_id": {
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
                        "cr_id",
                        "surrogate_id",
                        "nbf",
                        "rs_description",
                        "version",
                        "role",
                        "exp",
                        "operator",
                        "iat",
                        "subject_id"
                      ],
                      "type": "object"
                    },
                    "consent_receipt_part": {
                      "properties": {
                        "ki_cr": {
                          "properties": {},
                          "type": "object"
                        }
                      },
                      "required": [
                        "ki_cr"
                      ],
                      "type": "object"
                    },
                    "extension_part": {
                      "properties": {
                        "extensions": {
                          "properties": {},
                          "type": "object"
                        }
                      },
                      "required": [
                        "extensions"
                      ],
                      "type": "object"
                    },
                    "role_specific_part": {
                      "properties": {
                        "source_cr_id": {
                          "type": "string"
                        },
                        "usage_rules": {
                          "items": {
                            "type": "string"
                          },
                          "type": "array"
                        }
                      },
                      "required": [
                        "source_cr_id",
                        "usage_rules"
                      ],
                      "type": "object"
                    }
                  },
                  "required": [
                    "common_part",
                    "role_specific_part",
                    "consent_receipt_part",
                    "extension_part"
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
            },
            "consent_status_record_payload": {
              "properties": {
                "attributes": {
                  "properties": {
                    "consent_status": {
                      "type": "string"
                    },
                    "cr_id": {
                      "type": "string"
                    },
                    "iat": {
                      "type": "integer"
                    },
                    "prev_record_id": {
                      "type": "string"
                    },
                    "record_id": {
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
                    "cr_id",
                    "surrogate_id",
                    "prev_record_id",
                    "version",
                    "record_id",
                    "iat",
                    "consent_status"
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
            "consent_record_payload",
            "consent_status_record_payload"
          ],
          "type": "object"
        },
        "source": {
          "properties": {
            "consent_record_payload": {
              "properties": {
                "attributes": {
                  "properties": {
                    "common_part": {
                      "properties": {
                        "cr_id": {
                          "type": "string"
                        },
                        "exp": {
                          "type": "integer"
                        },
                        "iat": {
                          "type": "integer"
                        },
                        "nbf": {
                          "type": "integer"
                        },
                        "operator": {
                          "type": "string"
                        },
                        "role": {
                          "type": "string"
                        },
                        "rs_description": {
                          "properties": {
                            "resource_set": {
                              "properties": {
                                "dataset": {
                                  "items": {
                                    "properties": {
                                      "dataset_id": {
                                        "type": "string"
                                      },
                                      "distribution_id": {
                                        "type": "string"
                                      },
                                      "distribution_url": {
                                        "type": "string"
                                      }
                                    },
                                    "required": [
                                      "distribution_url",
                                      "distribution_id",
                                      "dataset_id"
                                    ],
                                    "type": "object"
                                  },
                                  "type": "array"
                                },
                                "rs_id": {
                                  "type": "string"
                                }
                              },
                              "required": [
                                "rs_id",
                                "dataset"
                              ],
                              "type": "object"
                            }
                          },
                          "required": [
                            "resource_set"
                          ],
                          "type": "object"
                        },
                        "slr_id": {
                          "type": "string"
                        },
                        "subject_id": {
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
                        "cr_id",
                        "surrogate_id",
                        "nbf",
                        "rs_description",
                        "version",
                        "role",
                        "exp",
                        "operator",
                        "iat",
                        "subject_id"
                      ],
                      "type": "object"
                    },
                    "consent_receipt_part": {
                      "properties": {
                        "ki_cr": {
                          "properties": {},
                          "type": "object"
                        }
                      },
                      "required": [
                        "ki_cr"
                      ],
                      "type": "object"
                    },
                    "extension_part": {
                      "properties": {
                        "extensions": {
                          "properties": {},
                          "type": "object"
                        }
                      },
                      "required": [
                        "extensions"
                      ],
                      "type": "object"
                    },
                    "role_specific_part": {
                      "properties": {
                        "pop_key": {
                          "properties": {},
                          "type": "object"
                        },
                        "token_issuer_key": {
                          "properties": {},
                          "type": "object"
                        }
                      },
                      "required": [
                        "pop_key",
                        "token_issuer_key"
                      ],
                      "type": "object"
                    }
                  },
                  "required": [
                    "common_part",
                    "role_specific_part",
                    "consent_receipt_part",
                    "extension_part"
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
            },
            "consent_status_record_payload": {
              "properties": {
                "attributes": {
                  "properties": {
                    "consent_status": {
                      "type": "string"
                    },
                    "cr_id": {
                      "type": "string"
                    },
                    "iat": {
                      "type": "integer"
                    },
                    "prev_record_id": {
                      "type": "string"
                    },
                    "record_id": {
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
                    "cr_id",
                    "surrogate_id",
                    "prev_record_id",
                    "version",
                    "record_id",
                    "iat",
                    "consent_status"
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
            "consent_record_payload",
            "consent_status_record_payload"
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

schema_consent_status_new = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "properties": {
        "attributes": {
          "properties": {
            "consent_status": {
              "type": "string"
            },
            "cr_id": {
              "type": "string"
            },
            "iat": {
              "type": "integer"
            },
            "prev_record_id": {
              "type": "string"
            },
            "record_id": {
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
            "cr_id",
            "surrogate_id",
            "prev_record_id",
            "version",
            "record_id",
            "iat",
            "consent_status"
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
    "data"
  ],
  "type": "object"
}


schema_consent_status_signed_new = {
  "$schema": "http://json-schema.org/draft-04/schema#",
  "definitions": {},
  "id": "http://example.com/example.json",
  "properties": {
    "data": {
      "properties": {
        "csr": {
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
        "csr_payload": {
          "properties": {
            "attributes": {
              "properties": {
                "consent_status": {
                  "type": "string"
                },
                "cr_id": {
                  "type": "string"
                },
                "iat": {
                  "type": "integer"
                },
                "prev_record_id": {
                  "type": "string"
                },
                "record_id": {
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
                "cr_id",
                "surrogate_id",
                "prev_record_id",
                "version",
                "record_id",
                "iat",
                "consent_status"
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
        "csr_payload",
        "csr"
      ],
      "type": "object"
    }
  },
  "required": [
    "data"
  ],
  "type": "object"
}

