# -*- coding: utf-8 -*-
from kombu import Exchange, Queue

TIMEOUT = 8
KEYTYPE = "EC256" # (RSA|EC256)
KEYSIZE = 512 # Affects only if using RSA key


UID = 'Operator112'




SERVICE_REGISTRY_SEARCH_DOMAIN = "http://178.62.229.148:8081"



SERVICE_REGISTRY_SEARCH_ENDPOINT = "/api/v1/services/"




NOT_AFTER_INTERVAL = 2592000 # 30 days in seconds.


# Name of host to connect to. Default: use the local host via a UNIX socket (where applicable)

MYSQL_HOST = 'localhost'


 # User to authenticate as. Default: current effective user.

MYSQL_USER = 'operator'


# Password to authenticate with. Default: no password.

MYSQL_PASSWORD = 'MynorcA'


# Database to use. Default: no default database.

MYSQL_DB = 'MyDataOperator'


# TCP port of MySQL server. Default: 3306.

MYSQL_PORT = 3306




# TODO give these as parameter to init AccountManagerHandler


ACCOUNT_MANAGEMENT_URL = "http://myaccount.dy.fi/" 




ACCOUNT_MANAGEMENT_USER = "test_sdk"



ACCOUNT_MANAGEMENT_PASSWORD = "test_sdk_pw"



# Setting to /tmp or other ramdisk makes it faster.


DATABASE_PATH = "./db_Operator.sqlite" 




SELERY_BROKER_URL = 'redis://localhost:6379/0'



SELERY_RESULT_BACKEND = 'redis://localhost:6379/0'





CERT_PATH = "./service_key.jwk"



CERT_KEY_PATH = "./service_key.jwk"



CERT_PASSWORD_PATH = "./cert_pw"




OPERATOR_URL = "http://localhost:5000"




RETURN_URL = "http://localhost:5000/"




OPERATOR_UID = "41e19fcd-1951-455f-9169-a303f990f52d"




OPERATOR_ROOT_PATH = "/api/1.3"



OPERATOR_CR_PATH = "/cr"



OPERATOR_SLR_PATH = "/slr"



SERVICE_URL = "http://localhost:7000"



DEBUG_MODE = True




CELERY_QUEUES = (
    Queue('op_queue', Exchange('op_queue'), routing_key='op_queue'),
)

CELERY_DEFAULT_QUEUE = 'op_queue'

CELERY_ROUTES = {
    'CR_Installer': {'queue': 'op_queue','routing_key': "op_queue"},
}