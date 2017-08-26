# -*- coding: utf-8 -*-
from requests import post
from factory import create_celery_app
import logging
from helpers_op import Sequences
# Logging
debug_log = logging.getLogger("debug")

logger = logging.getLogger("sequence")
try:
    from restapi_logging_handler import RestApiHandler

    restapihandler = RestApiHandler("http://172.17.0.1:9004/")
    logger.addHandler(restapihandler)

except Exception as e:
    pass


celery = create_celery_app()

@celery.task(ignore_result=True)
def CR_installer(crs_csrs_payload, sink_url, source_url):
    # Get these as parameter or inside crs_csrs_payload
    endpoint = "/api/1.3/cr/cr_management"
    debug_log.info("CR_installer got following cr jsons:\n{}".format(crs_csrs_payload))
    source = post(source_url+endpoint, json=crs_csrs_payload["source"])
    debug_log.info("Request to install CR for source {} returned {}, {}, {}".format(source.url,
                                                                                    source.reason,
                                                                                    source.status_code,
                                                                                    source.text))

    sink = post(sink_url+endpoint, json=crs_csrs_payload["sink"])
    debug_log.info("Request to install CR for sink {} returned {}, {}, {}".format(sink.url,
                                                                                  sink.reason,
                                                                                  sink.status_code,
                                                                                  sink.text))
