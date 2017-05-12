# -*- coding: utf-8 -*-
"""
    wsgi
    ~~~~
    overholt wsgi module
    This is the beginning of all, it loads up the modules wanted using DispatcherMiddleware
    The RestApiHandler section is for debugging purposes and enables generating JSequence styled descriptions.
    It is optional and enabled only if RestApiHandler from restapi_logging_handler library is found.
"""

import logging

from werkzeug.serving import run_simple
from werkzeug.wsgi import DispatcherMiddleware

import Operator_CR
import Operator_Root
import Operator_SLR

logger = logging.getLogger("sequence")
try:
    from restapi_logging_handler import RestApiHandler

    restapihandler = RestApiHandler("http://172.17.0.1:9004/")
    logger.addHandler(restapihandler)

except Exception as e:
    pass
logger.setLevel(logging.INFO)

debug_log = logging.getLogger("debug")
logging.basicConfig()
debug_log.setLevel(logging.DEBUG)

from instance.settings import OPERATOR_ROOT_PATH, OPERATOR_CR_PATH, OPERATOR_SLR_PATH

application = DispatcherMiddleware(Operator_Root.create_app(),
                                   {OPERATOR_ROOT_PATH + OPERATOR_CR_PATH: Operator_CR.create_app(),
                                    OPERATOR_ROOT_PATH + OPERATOR_SLR_PATH: Operator_SLR.create_app()})

if __name__ == "__main__":
    run_simple('0.0.0.0', 5000, application, use_reloader=False, use_debugger=False, threaded=True)
