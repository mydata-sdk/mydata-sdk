# -*- coding: utf-8 -*-
from kombu import Exchange, Queue

TIMEOUT = 8
KEYTYPE = "EC256" # (RSA|EC256)
KEYSIZE = 512


IS_SINK = True



IS_SOURCE = True



SINK_URL = "http://service_component_sink:7000"


# Name of host to connect to. Default: use the local host via a UNIX socket (where applicable)

MYSQL_HOST = 'localhost'


 # User to authenticate as. Default: current effective user.

MYSQL_USER = 'service'


# Password to authenticate with. Default: no password.

MYSQL_PASSWORD = 'MynorcA'


# Database to use. Default: no default database.

MYSQL_DB = 'db_Srv'


# TCP port of MySQL server. Default: 3306.

MYSQL_PORT = 3306






# Setting to /tmp or other ramdisk makes it faster.


DATABASE_PATH = "./db_Operator.sqlite" 





SELERY_BROKER_URL = 'redis://localhost:6379/1'



SELERY_RESULT_BACKEND = 'redis://localhost:6379/1'




CERT_PATH = "./service_key.jwk"



CERT_KEY_PATH = "./service_key.jwk"



CERT_PASSWORD_PATH = "./cert_pw"





SERVICE_URL = "http://localhost:2000"



OPERATOR_URL = "http://localhost:5000"



SERVICE_ID = "SRVMGMNT-CHANGE_ME"



SERVICE_ROOT_PATH = "/api/1.3"



SERVICE_CR_PATH = "/cr"



SERVICE_SLR_PATH = "/slr"



LOCK_WAIT_TIME = 4




DEBUG_MODE = True


CELERY_QUEUES = (
    Queue('srv_queue', Exchange('srv_queue'), routing_key='srv_queue'),
)

CELERY_DEFAULT_QUEUE = 'srv_queue'

CELERY_ROUTES = {
    'get_AuthToken': {'queue': 'srv_queue', 'routing_key': "srv_queue"}
}