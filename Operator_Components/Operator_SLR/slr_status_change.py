# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import traceback
from json import loads

from flask import Blueprint, current_app, render_template_string, make_response, redirect
from flask_cors import CORS
from flask_restful import Resource, Api, request
from requests import get, post
from requests.exceptions import ConnectionError, Timeout

from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_op import Helpers, ServiceRegistryHandler, Sequences, get_am, base_token_tool
'''

'''

# Blueprint and Flask api stuff
api_SLR_Start = Blueprint("api_SLR_change", __name__)
CORS(api_SLR_Start)
api = Api()
api.init_app(api_SLR_Start)


# Logger stuff
debug_log = logging.getLogger("debug")
sq = Sequences("Operator_Components Mgmnt")


class SlrStatus(Resource):
    def __init__(self):
        """
        
        """
        super(SlrStatus, self).__init__()
        self.service_registry_handler = ServiceRegistryHandler(current_app.config["SERVICE_REGISTRY_SEARCH_DOMAIN"],
                                                               current_app.config["SERVICE_REGISTRY_SEARCH_ENDPOINT"])
        self.request_timeout = current_app.config["TIMEOUT"]
        self.uid = current_app.config["UID"]
        self.helper = Helpers(current_app.config)
        self.store_session = self.helper.store_session

    @error_handler
    def post(self, account_id, service_id, slr_id):
        """
        
        :param slr_id:      Id of SLR we want to change
        :param account_id:  Account Manager user id
        :param service_id:  Service id as in Service Registry
        """
        debug_log.info("#### Request to change SLR status with parameters: account_id ({}), service_id ({}), slr_id ({})"
                       .format(account_id, service_id, slr_id))
        try:
            am = get_am(current_app, request.headers)
            # Verify Api-Key-User
            key_check = am.verify_user_key(account_id)
            debug_log.info("Verifying User Key resulted: {}".format(key_check))
            try:
                # Get SLR
                slr = am.get_slr(slr_id, account_id)
                decoded_slr = base_token_tool.decode_payload(slr["data"]["attributes"]["payload"])
                surrogate_id = decoded_slr["surrogate_id"]
                last_ssr = am.get_last_slr_status(slr_id)
                last_ssr_payload = base_token_tool.decode_payload(last_ssr["data"]["attributes"]["payload"])
                if last_ssr_payload["sl_status"] != "Active":
                    raise TypeError("This SLR isn't Active to begin with.")
                prev_record_id = last_ssr_payload["record_id"]
                debug_log.info("Got Decoded SLR Payload:\n {}".format(decoded_slr))
                consents = am.get_crs(slr_id, account_id, pairs=True)

                # Loop trough the consents and fetch pairs.
                # Step redundant since endpoint at Account gives us paired consent as well.
            except Exception as e:
                raise e

            try:
                def csr_active(csr):
                    # Implement
                    return True

                # Get CR statuses
                crs_to_disable = []
                if False:  # TODO: Implement once we have real consents
                    for consent in consents:
                        cr_id = consent["data"]["id"]
                        raw_csr = am.get_last_csr(cr_id)
                        if csr_active(raw_csr):
                            crs_to_disable.append(cr_id)

                pass
            except Exception as e:
                raise e

            try:
                # Create new SLR status

                created_ssr = am.create_ssr(surrogate_id=surrogate_id,
                                            slr_id=slr_id,
                                            sl_status="Removed",
                                            prev_record_id=prev_record_id,
                                            )


                pass
            except Exception as e:
                raise e

            try:
                # Notify Service of SLR status chanege
                service_url = self.service_registry_handler.getService_url(service_id)
                endpoint = "/api/1.3/slr/status"
                req = post(service_url+endpoint, json=created_ssr)
                debug_log.debug("Posted SSR to service:\n{}  {}  {}  {}"
                                .format(req.status_code, req.reason, req.text, req.content))

                return created_ssr
                pass


            except Exception as e:
                raise e

        except DetailedHTTPException as e:
            raise e
        except Exception as e:
            raise DetailedHTTPException(status=500,
                                        title="Something went really wrong during SLR Status Change.",
                                        detail="Error: {}".format(repr(e)),
                                        exception=e,
                                        trace=traceback.format_exc(limit=100).splitlines())

api.add_resource(SlrStatus, '/account/<string:account_id>/service/<string:service_id>/slr/<string:slr_id>')
