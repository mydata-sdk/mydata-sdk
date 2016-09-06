# -*- coding: utf-8 -*-
TIMEOUT = 8
KEYSIZE = 512

DATABASE_PATH = "./db_Srv.sqlite"  # Setting to /tmp or other ramdisk makes it faster.

CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

CERT_PATH = "./service_key.jwk"
CERT_KEY_PATH = "./service_key.jwk"
CERT_PASSWORD_PATH = "./cert_pw"

SERVICE_URL = "http://localhost:2000"
OPERATOR_URL = "http://localhost:5000"


SERVICE_ROOT_PATH = "/api/1.2"
SERVICE_CR_PATH ="/cr"
SERVICE_SLR_PATH="/slr"



