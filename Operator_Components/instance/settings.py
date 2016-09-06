# -*- coding: utf-8 -*-
TIMEOUT = 8
KEYSIZE = 512

ACCOUNT_MANAGEMENT_URL="http://9f31243b.ngrok.io/"  # TODO give these as parameter to init AccountManagerHandler
ACCOUNT_MANAGEMENT_USER="test_sdk"
ACCOUNT_MANAGEMENT_PASSWORD="test_sdk_pw"

DATABASE_PATH = "./db_Operator.sqlite"  # Setting to /tmp or other ramdisk makes it faster.

CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

CERT_PATH = "./service_key.jwk"
CERT_KEY_PATH = "./service_key.jwk"
CERT_PASSWORD_PATH = "./cert_pw"

OPERATOR_UID = "41e19fcd-1951-455f-9169-a303f990f52d"

OPERATOR_ROOT_PATH="/api/1.2"
OPERATOR_CR_PATH="/cr"
OPERATOR_SLR_PATH="/slr"

SERVICE_URL = "http://localhost:7000"
