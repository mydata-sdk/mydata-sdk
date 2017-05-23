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
import json
from base64 import urlsafe_b64decode
from random import choice, randint
from string import lowercase
from time import time
from uuid import uuid4
from jsonschema import validate, ValidationError, SchemaError
from jwcrypto import jwk
from jwcrypto import jws

default_headers = {'Content-Type': 'application/json', 'Accept-Charset': 'utf-8', 'Accept': 'application/json'}

def get_epoch():
    return int(time())


def get_unique_string():
    return str(uuid4())


def generate_string(n):
    return "".join(choice(lowercase) for i in range(n))


def is_json(json_object=None):
    try:
        json.loads(json_object)
    except Exception as exp:
        raise
    else:
        return True


def validate_json(json_object=None, json_schema=None):
    if json_object is None:
        raise AttributeError("Provide json_object as parameter")
    if json_schema is None:
        raise AttributeError("Provide json_schema as parameter")

    try:
        json_object = json.loads(json_object)
    except Exception as exp:
        raise

    try:
        validate(json_object, json_schema)
    except ValidationError as exp:
        raise
    except SchemaError as exp:
        raise
    except Exception as exp:
        raise
    else:
        return True


def account_create(username=None, password=None, username_length=15, password_length=15, firstname_length=15, lastname_length=15, invalid_type=False):
    """
    Create valid Account
    :return: account, username, password
    """
    if username is None:
        username = generate_string(n=username_length)
    if password is None:
        password = generate_string(n=password_length)
    firstname = generate_string(n=firstname_length)
    lastname = generate_string(n=lastname_length)

    if invalid_type:
        resource_type = "Acc"
    else:
        resource_type = "Account"


    account = {
      "data": {
        "type": resource_type,
        "attributes": {
          "firstName": firstname,
          "lastName": lastname,
          "username": username,
          "password": password
        }
      }
    }

    account = json.dumps(account)

    return account, username, password


def generate_sl_init_sink(slr_id=None, misformatted_payload=False):

    if slr_id is None:
        slr_id = get_unique_string()

    code = str(randint(100, 10000))
    pop_key_object, pop_key_private_json, pop_key_public_json, kid = gen_jwk_key(prefix="sink")
    pop_key = json.loads(pop_key_public_json)

    if misformatted_payload:
        del pop_key['kty']
        del pop_key['x']

    sl_init_payload = {
      "code": code,
      "data": {
        "attributes": {
          "slr_id": slr_id,
          "pop_key": pop_key
        }
      }
    }

    payload = json.dumps(sl_init_payload)

    return payload, code, slr_id, pop_key


def generate_sl_init_source(slr_id=None, misformatted_payload=False):

    if slr_id is None:
        slr_id = get_unique_string()

    code = str(randint(100, 10000))

    sl_init_payload = {
      "code": code,
      "data": {
        "attributes": {
          "slr_id": slr_id
        }
      }
    }

    if misformatted_payload:
        del sl_init_payload['code']

    payload = json.dumps(sl_init_payload)

    return payload, code, slr_id


def generate_sl_payload(slr_id=None, operator_id=None, operator_key=None, service_id=None, surrogate_id=None, misformatted_payload=False):

    if slr_id is None:
        raise AttributeError("Provide operator_id as parameter")
    if operator_id is None:
        raise AttributeError("Provide operator_id as parameter")
    if operator_key is None:
        raise AttributeError("Provide operator_key as parameter")
    if service_id is None:
        raise AttributeError("Provide service_id as parameter")
    if surrogate_id is None:
        raise AttributeError("Provide surrogate_id as parameter")

    sl_payload = {
      "code": str(randint(100, 10000)),
      "data": {
        "type": "string",
        "attributes": {
          "version": "1.3",
          "link_id": slr_id,
          "operator_id": operator_id,
          "service_id": service_id,
          "surrogate_id": surrogate_id,
          "operator_key": operator_key,
          "iat": get_epoch()
        }
      }
    }

    if misformatted_payload:
        del sl_payload['data']['attributes']['surrogate_id']
        del sl_payload['data']['attributes']['iat']

    payload = json.dumps(sl_payload)

    return payload


def generate_sl_store_payload(service_key=None, service_kid=None, slr_id=None, slr_signed=None, surrogate_id=None, record_id=None, misformatted_payload=False, misformatted_signature=False):

    if slr_id is None:
        raise AttributeError("Provide operator_id as parameter")
    if slr_signed is None:
        raise AttributeError("Provide slr_signed as parameter")
    if surrogate_id is None:
        raise AttributeError("Provide surrogate_id as parameter")
    if service_key is None:
        raise AttributeError("Provide service_key as parameter")
    if service_kid is None:
        raise AttributeError("Provide service_kid as parameter")

    if record_id is None:
        record_id = get_unique_string()

    # Sign SLR on behalf of service
    slr_double_signed = sign_jws(jws_to_sign=slr_signed['attributes'], jwk_key=service_key, jwk_kid=service_kid)

    slr_data = slr_signed
    slr_data['attributes'] = slr_double_signed

    sl_store_payload = {
      "code": str(randint(100, 10000)),
      "data": {
        "slr": slr_data,
        "ssr": {
          "type": "ServiceLinkStatusRecord",
          "attributes": {
            "version": "1.3",
            "record_id": record_id,
            "surrogate_id": surrogate_id,
            "slr_id": slr_id,
            "sl_status": "Active",
            "iat": get_epoch(),
            "prev_record_id": ""
          }
        }
      }
    }

    if misformatted_payload:
        del sl_store_payload['data']['slr']['attributes']['payload']
        del sl_store_payload['data']['ssr']['attributes']['iat']

    if misformatted_signature:
        sl_store_payload['data']['slr']['attributes']['signatures'][0]['signature'] = get_unique_string()
        sl_store_payload['data']['slr']['attributes']['signatures'][1]['signature'] = get_unique_string()

    payload = json.dumps(sl_store_payload)

    return payload


def generate_sls_store_payload(slr_id=None, surrogate_id=None, record_id=None, status="Active", prev_record_id=None, misformatted_payload=False):

    if slr_id is None:
        raise AttributeError("Provide operator_id as parameter")
    if surrogate_id is None:
        raise AttributeError("Provide surrogate_id as parameter")
    if prev_record_id is None:
        raise AttributeError("Provide prev_record_id as parameter")

    if record_id is None:
        record_id = get_unique_string()

    sl_store_payload = {
        "data": {
            "type": "ServiceLinkStatusRecord",
            "attributes": {
                "version": "1.3",
                "record_id": record_id,
                "surrogate_id": surrogate_id,
                "slr_id": slr_id,
                "sl_status": status,
                "iat": get_epoch(),
                "prev_record_id": prev_record_id
            }
        }
    }

    if misformatted_payload:
        del sl_store_payload['data']['attributes']['version']
        del sl_store_payload['data']['attributes']['iat']

    payload = json.dumps(sl_store_payload)

    return payload


def generate_signed_ssr_store_payload(slr_id=None, surrogate_id=None, record_id=None, status="Active", prev_record_id=None, operator_key=None, operator_kid=None, misformatted_payload=False):

    if slr_id is None:
        raise AttributeError("Provide operator_id as parameter")
    if surrogate_id is None:
        raise AttributeError("Provide surrogate_id as parameter")
    if prev_record_id is None:
        raise AttributeError("Provide prev_record_id as parameter")
    if operator_key is None:
        raise AttributeError("Provide operator_key as parameter")
    if operator_kid is None:
        raise AttributeError("Provide operator_kid as parameter")

    if record_id is None:
        record_id = get_unique_string()

    ssr = {
        "data": {
            "type": "ServiceLinkStatusRecord",
            "attributes": {
                "version": "1.3",
                "record_id": record_id,
                "surrogate_id": surrogate_id,
                "slr_id": slr_id,
                "sl_status": status,
                "iat": get_epoch(),
                "prev_record_id": prev_record_id
            }
        }
    }

    # Sign SSR on behalf of operator
    ssr_signed = sign_payload_jws(payload_to_sign=ssr['data']['attributes'], jwk_key=operator_key, jwk_kid=operator_kid)

    ssr_payload = {
      "data": {
        "ssr": {
          "type": "ServiceLinkStatusRecord",
          "id": record_id,
          "attributes": ssr_signed
        },
        "ssr_payload": {
          "attributes": ssr['data']['attributes']
        }
      }
    }

    if misformatted_payload:
        del ssr_payload['data']['ssr_payload']['attributes']['surrogate_id']

    payload = json.dumps(ssr_payload)

    return payload


def generate_consent_payload(
        source_surrogate_id=None,
        source_slr_id=None,
        operator_id=None,
        source_subject_id=None,
        source_role="Source",
        sink_pop_key=None,
        operator_pub_key=None,
        sink_surrogate_id=None,
        sink_slr_id=None,
        sink_subject_id=None,
        sink_role="Sink",
        misformatted_payload=False,
        source_cr_id_fault=False,
        sink_cr_id_fault=False,
        source_surrogate_id_fault=False,
        sink_surrogate_id_fault=False
):

    if source_surrogate_id is None:
        raise AttributeError("Provide source_surrogate_id as parameter")
    if source_slr_id is None:
        raise AttributeError("Provide source_slr_id as parameter")
    if operator_id is None:
        raise AttributeError("Provide operator_id as parameter")
    if source_subject_id is None:
        raise AttributeError("Provide source_subject_id as parameter")
    if source_role is None:
        raise AttributeError("Provide source_role as parameter")
    if sink_pop_key is None:
        raise AttributeError("Provide sink_pop_key as parameter")
    if operator_pub_key is None:
        raise AttributeError("Provide operator_pub_key as parameter")
    if sink_surrogate_id is None:
        raise AttributeError("Provide sink_surrogate_id as parameter")
    if sink_slr_id is None:
        raise AttributeError("Provide sink_slr_id as parameter")
    if sink_subject_id is None:
        raise AttributeError("Provide sink_subject_id as parameter")
    if sink_role is None:
        raise AttributeError("Provide sink_role as parameter")
    if source_cr_id_fault is None:
        raise AttributeError("Provide source_cr_id_fault as parameter")
    if sink_cr_id_fault is None:
        raise AttributeError("Provide sink_cr_id_fault as parameter")
    if source_surrogate_id_fault is None:
        raise AttributeError("Provide source_surrogate_id_fault as parameter")
    if sink_surrogate_id_fault is None:
        raise AttributeError("Provide sink_surrogate_id_fault as parameter")

    source_cr_id = "source-" + get_unique_string()
    source_csr_id = "source-" + get_unique_string()
    # CR id mismatch
    if source_cr_id_fault:
        source_status_cr_id = "wrong-" + source_cr_id
    else:
        source_status_cr_id = source_cr_id
    # Surrogate id mismatch
    if source_surrogate_id_fault:
        source_status_surrogate_id = "wrong-" + source_surrogate_id
    else:
        source_status_surrogate_id = source_surrogate_id

    sink_cr_id = "sink-" + get_unique_string()
    sink_csr_id = "sink-" + get_unique_string()
    # CD id mismatch
    if sink_cr_id_fault:
        sink_status_cr_id = "wrong-" + sink_cr_id
    else:
        sink_status_cr_id = sink_cr_id
    # Surrogate id mismatch
    if sink_surrogate_id_fault:
        sink_status_surrogate_id = "wrong-" + sink_surrogate_id
    else:
        sink_status_surrogate_id = sink_surrogate_id

    iat = get_epoch()
    nbf = iat
    exp = iat + 1000

    consent_payload = {
      "data": {
        "source": {
          "consent_record_payload": {
            "type": "ConsentRecord",
            "attributes": {
              "common_part": {
                "version": "1.3",
                "cr_id": source_cr_id,
                "surrogate_id": source_surrogate_id,
                "slr_id": source_slr_id,
                "operator": operator_id,
                "subject_id": source_subject_id,
                "role": source_role,
                "iat": iat,
                "nbf": nbf,
                "exp": exp,
                "rs_description": {
                  "resource_set": {
                    "rs_id": get_unique_string(),
                    "dataset": [
                      {
                        "dataset_id": get_unique_string(),
                        "distribution_id": get_unique_string(),
                        "distribution_url": get_unique_string()
                      }
                    ]
                  }
                }
              },
              "role_specific_part": {
                "pop_key": sink_pop_key,
                "token_issuer_key": operator_pub_key
              },
              "consent_receipt_part": {
                "ki_cr": {}
              },
              "extension_part": {
                "extensions": {}
              }
            }
          },
          "consent_status_record_payload": {
            "type": "ConsentStatusRecord",
            "attributes": {
              "version": "1.3",
              "record_id": source_csr_id,
              "surrogate_id": source_status_surrogate_id,
              "cr_id": source_status_cr_id,
              "consent_status": "Active",
              "iat": iat,
              "prev_record_id": "NULL"
            }
          }
        },
        "sink": {
          "consent_record_payload": {
            "type": "ConsentRecord",
            "attributes": {
              "common_part": {
                "version": "1.3",
                "cr_id": sink_cr_id,
                "surrogate_id": sink_surrogate_id,
                "slr_id": sink_slr_id,
                "operator": operator_id,
                "subject_id": sink_subject_id,
                "role": sink_role,
                "iat": iat,
                "nbf": nbf,
                "exp": exp,
                "rs_description": {
                  "resource_set": {
                    "rs_id": get_unique_string(),
                    "dataset": [
                      {
                        "dataset_id": get_unique_string(),
                        "distribution_id": get_unique_string(),
                        "distribution_url": get_unique_string()
                      }
                    ]
                  }
                }
              },
              "role_specific_part": {
                "source_cr_id": "string",
                "usage_rules": [
                  "Rule 1",
                  "Rule 2",
                  "Rule 3",
                  "Rule 4"
                ]
              },
              "consent_receipt_part": {
                "ki_cr": {}
              },
              "extension_part": {
                "extensions": {}
              }
            }
          },
          "consent_status_record_payload": {
            "type": "ConsentStatusRecord",
            "attributes": {
              "version": "1.3",
              "record_id": sink_csr_id,
              "surrogate_id": sink_status_surrogate_id,
              "cr_id": sink_status_cr_id,
              "consent_status": "Active",
              "iat": iat,
              "prev_record_id": "NULL"
            }
          }
        }
      }
    }

    if misformatted_payload:
        del consent_payload['data']['source']['consent_status_record_payload']['attributes']['iat']

    payload = json.dumps(consent_payload)

    return payload, source_cr_id, source_csr_id, sink_cr_id, sink_csr_id


def generate_consent_status_payload(
        surrogate_id=None,
        cr_id=None,
        consent_status=None,
        prev_record_id=None,
        misformatted_payload=False,
        cr_id_fault=False
):
    if surrogate_id is None:
        raise AttributeError("Provide surrogate_id as parameter")
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if consent_status is None:
        raise AttributeError("Provide consent_status as parameter")
    if prev_record_id is None:
        raise AttributeError("Provide prev_record_id as parameter")
    if cr_id_fault is None:
        raise AttributeError("Provide cr_id_fault as parameter")

    # Status record ID
    record_id = "status-" + get_unique_string()

    # CR id mismatch
    if cr_id_fault:
        cr_id = "wrong-" + cr_id

    iat = get_epoch()

    consent_payload = {
      "data": {
        "type": "ConsentStatusRecord",
        "attributes": {
          "version": "1.3",
          "record_id": record_id,
          "surrogate_id": surrogate_id,
          "cr_id": cr_id,
          "consent_status": consent_status,
          "iat": iat,
          "prev_record_id": prev_record_id
        }
      }
    }

    if misformatted_payload:
        del consent_payload['data']['attributes']['iat']

    payload = json.dumps(consent_payload)

    return payload, record_id


def generate_consent_status_payload_signed(
        surrogate_id=None,
        cr_id=None,
        consent_status=None,
        prev_record_id=None,
        misformatted_payload=False,
        cr_id_fault=False,
        operator_key=None,
        operator_kid=None
):
    if surrogate_id is None:
        raise AttributeError("Provide surrogate_id as parameter")
    if cr_id is None:
        raise AttributeError("Provide cr_id as parameter")
    if consent_status is None:
        raise AttributeError("Provide consent_status as parameter")
    if prev_record_id is None:
        raise AttributeError("Provide prev_record_id as parameter")
    if cr_id_fault is None:
        raise AttributeError("Provide cr_id_fault as parameter")
    if operator_key is None:
        raise AttributeError("Provide operator_key as parameter")
    if operator_kid is None:
        raise AttributeError("Provide operator_kid as parameter")

    # Status record ID
    record_id = "status-" + get_unique_string()

    # CR id mismatch
    if cr_id_fault:
        cr_id = "wrong-" + cr_id

    iat = get_epoch()

    csr_payload = {
      "data": {
        "type": "ConsentStatusRecord",
        "attributes": {
          "version": "1.3",
          "record_id": record_id,
          "surrogate_id": surrogate_id,
          "cr_id": cr_id,
          "consent_status": consent_status,
          "iat": iat,
          "prev_record_id": prev_record_id
        }
      }
    }

    csr_signed = sign_payload_jws(payload_to_sign=csr_payload['data']['attributes'], jwk_key=operator_key, jwk_kid=operator_kid)

    payload = {
        "data": {
            "csr": {
                "type": "ServiceLinkStatusRecord",
                "id": record_id,
                "attributes": csr_signed
            },
            "csr_payload": {
                "attributes": csr_payload['data']['attributes']
            }
        }
    }

    if misformatted_payload:
        del payload['data']['csr_payload']['attributes']['consent_status']

    payload = json.dumps(payload)

    return payload, record_id

#############
#############
# JWS & JWK #
#############
#############


def jwk_object_to_json(jwk_object=None):
    """
    Exports JWK object to JSON presentation

    :param jwk_object:
    :return: JSON presentation of JWK object
    """
    if jwk_object is None:
        raise AttributeError("Provide jwk_object as parameter")

    try:
        jwk_private_json = jwk_object.export()
        jwk_public_json = jwk_object.export(private_key=False)
    except Exception as exp:
        raise
    else:
        return jwk_private_json, jwk_public_json


def gen_key_as_jwk(kid=None):
    """
    Generates JWK (JSON Web Key) object with JWCrypto's jwk module.
    - Module documentation: http://jwcrypto.readthedocs.io/en/stable/jwk.html

    :param kid: Key ID, https://tools.ietf.org/html/rfc7517#section-4.5
    :return: Generated JWK object
    """
    if kid is None:
        raise AttributeError("Provide kid as parameter")
    if not isinstance(kid, str):
        raise TypeError("kid MUST be str")

    gen = {"generate": "EC", "cvr": "P-256", "kid": kid}

    try:
        jwk_key = jwk.JWK(**gen)
        jwk_key_private_json, jwk_key_public_json = jwk_object_to_json(jwk_object=jwk_key)
    except Exception as exp:
        raise
    else:
        return jwk_key, jwk_key_private_json, jwk_key_public_json


def gen_jwk_key(prefix="key"):
    """
    Generate JWK

    :param prefix:
    :return: JWK
    """
    if prefix is None:
        raise AttributeError("Provide prefix as parameter")
    if not isinstance(prefix, str):
        raise TypeError("prefix MUST be str")

    kid = prefix + "-kid-" + str(uuid4())

    try:
        jwk_object, jwk_private_json, jwk_public_json = gen_key_as_jwk(kid=kid)
    except Exception as exp:
        raise
    else:
        return jwk_object, jwk_private_json, jwk_public_json, kid


def sign_jws(jws_to_sign=None, jwk_key=None, jwk_kid=None, alg="ES256"):
    if jws_to_sign is None:
        raise AttributeError("Provide jws_to_sign as parameter")
    if jwk_key is None:
        raise AttributeError("Provide jwk_key as parameter")
    if jwk_kid is None:
        raise AttributeError("Provide jwk_kid as parameter")
    if alg is None:
        raise AttributeError("Provide alg as parameter")

    unprotected_header = {'kid': jwk_kid}
    protected_header = {'alg': alg}
    unprotected_header_json = json.dumps(unprotected_header)
    protected_header_json = json.dumps(protected_header)

    print("JWS to Sign")
    print(json.dumps(jws_to_sign))
    slr_payload = jws_to_sign['payload']
    slr_payload += '=' * (-len(slr_payload) % 4)  # Fix incorrect padding of base64 string.
    slr_payload = urlsafe_b64decode(slr_payload.encode())
    slr_payload = json.loads(slr_payload.decode("utf-8"))

    print("SLR Decoded")
    print(json.dumps(slr_payload))

    print("Verification key")
    verification_key_json = slr_payload["cr_keys"][0]
    print(json.dumps(verification_key_json))
    verification_key = jwk.JWK(**verification_key_json)

    jws_object = jws.JWS()
    jws_object.deserialize(json.dumps(jws_to_sign))
    jws_object.verify(verification_key)  # Verifying changes the state of this object

    jws_object.add_signature(key=jwk_key, alg=alg, header=unprotected_header_json, protected=protected_header_json)

    jws_serialized = json.loads(jws_object.serialize())
    print("jws_serialized")
    print(jws_serialized)

    return jws_serialized


def sign_payload_jws(payload_to_sign=None, jwk_key=None, jwk_kid=None, alg="ES256"):
    if payload_to_sign is None:
        raise AttributeError("Provide payload_to_sign as parameter")
    if jwk_key is None:
        raise AttributeError("Provide jwk_key as parameter")
    if jwk_kid is None:
        raise AttributeError("Provide jwk_kid as parameter")
    if alg is None:
        raise AttributeError("Provide alg as parameter")

    unprotected_header = {'kid': jwk_kid}
    protected_header = {'alg': alg}
    unprotected_header_json = json.dumps(unprotected_header)
    protected_header_json = json.dumps(protected_header)

    jws_object = jws.JWS(json.dumps(payload_to_sign))
    jws_object.add_signature(key=jwk_key, alg=alg, header=unprotected_header_json, protected=protected_header_json)

    jws_serialized = json.loads(jws_object.serialize())
    print("jws_serialized")
    print(jws_serialized)

    return jws_serialized

