# -*- coding: utf-8 -*-
import time

__author__ = 'alpaloma'
import logging
import traceback
from json import dumps, loads
from DetailedHTTPException import DetailedHTTPException, error_handler
from Templates import Consent_form_Out
from flask import request, Blueprint, current_app
from flask_restful import Resource, Api
from helpers_op import AccountManagerHandler, Helpers, ServiceRegistryHandler, Sequences, get_am, api_logging
from op_tasks import CR_installer
from requests import post

# Logging
debug_log = logging.getLogger("debug")
sq = Sequences("OpMgmt")

# Init Flask
api_CR_blueprint = Blueprint("api_ConsentForm", __name__)
api = Api()
api.init_app(api_CR_blueprint)


class ConsentFormHandler(Resource):
    def __init__(self):
        super(ConsentFormHandler, self).__init__()
        self.am_url = current_app.config["ACCOUNT_MANAGEMENT_URL"]
        self.am_user = current_app.config["ACCOUNT_MANAGEMENT_USER"]
        self.am_password = current_app.config["ACCOUNT_MANAGEMENT_PASSWORD"]
        self.timeout = current_app.config["TIMEOUT"]
        self.debug_mode = current_app.config["DEBUG_MODE"]

        self.SH = ServiceRegistryHandler(current_app.config["SERVICE_REGISTRY_SEARCH_DOMAIN"],
                                         current_app.config["SERVICE_REGISTRY_SEARCH_ENDPOINT"])
        self.getService = self.SH.getService
        self.Helpers = Helpers(current_app.config)
        self.operator_url = current_app.config["OPERATOR_URL"]

    @error_handler
    @api_logging
    def get(self, account_id):
        """get
        :return: Returns Consent form to UI for user input.
        """
        sq.opt("UI Gets Consent Form from Operator")
        sq.activate()
        sq.message_from("OpUi", "GET Consent Form")
        sq.task("Verify MyData Account Key")
        am = get_am(current_app, request.headers)
        key_check = am.verify_user_key(account_id)
        debug_log.info("Verifying User Key resulted: {}".format(key_check))

        _consent_form = Consent_form_Out
        service_ids = request.args

        # Check that We don't have existing Active Consent between the two services
        sq.task("Check for existing SLR's and that no Active CR exist for the service pair.")
        am.check_existing_consent(service_id_sink=service_ids["sink"],
                                      service_id_source=service_ids["source"],
                                      account_id=account_id)

        sq.send_to("SrvReg", "Fetch service descriptions.")
        sq.reply_from("SrvReg", "Service Description.")
        sq.task("Create Consent Form template.")
        sink = self.getService(service_ids["sink"])
        _consent_form["sink"]["service_id"] = sink["serviceId"]
        _consent_form["sink"]["dataset"] = []  # Clear out template.
        for dataset in sink["serviceDescription"]["serviceDataDescription"][0]["dataset"]:
            item = {
                "dataset_id": dataset["datasetId"],
                "title": dataset["title"],
                "description": dataset["description"],
                "keyword": dataset["keyword"],
                "publisher": dataset["publisher"],
                "purposes": [{"title": purpose, "selected": "Bool", "required": "Bool"} for purpose in dataset["purpose"]]
            }

            _consent_form["sink"]["dataset"].append(item)

        source = self.getService(service_ids["source"])
        _consent_form["source"]["service_id"] = source["serviceId"]
        _consent_form["source"]["dataset"] = []  # Clear out template.
        for dataset in source["serviceDescription"]["serviceDataDescription"][0]["dataset"]:
            item = {
                "dataset_id": dataset["datasetId"],
                "title": dataset["title"],
                "description": dataset["description"],
                "keyword": dataset["keyword"],
                "publisher": dataset["publisher"],
                "distribution": {
                    "distribution_id": dataset["distribution"][0]["distributionId"],
                    "access_url": "{}{}{}".format(source["serviceInstance"][0]["domain"],
                                                  source["serviceInstance"][0]["serviceAccessEndPoint"][
                                                      "serviceAccessURI"]
                                                  , dataset["distribution"][0]["accessURL"]),

                },
                "component_specification_label": dataset["title"],
                "selected": "Bool"
                
            }
            _consent_form["source"]["dataset"].append(item)

        sq.task("Generate RS_ID for the template.")
        source_domain = source["serviceInstance"][0]["domain"]
        rs_id = self.Helpers.gen_rs_id(source_domain)
        sq.task("Store generated RS_ID")
        _consent_form["source"]["rs_id"] = rs_id

        sq.reply_to("OpUi", "Return Consent Form+RS_ID")
        sq.deactivate()
        sq.opt(end=True)
        return _consent_form

    @error_handler
    @api_logging
    def post(self, account_id):
        """post
        :return: Returns 201 when consent has been created
        """
        sq.opt("Operator Receives ConsentForm and creates CR/CSR")
        sq.message_from("OpUi", "POST ConsentForm")
        sq.activate()
        sq.task("Verify MyData Account Key")
        am = get_am(current_app, request.headers)
        key_check = am.verify_user_key(account_id)
        debug_log.info("Verifying User Key resulted: {}".format(key_check))

        _consent_form = request.json
        sink_srv_id = _consent_form["sink"]["service_id"]
        source_srv_id = _consent_form["source"]["service_id"]

        # Check that We don't have existing Active Consent between the two services
        am.check_existing_consent(service_id_sink=sink_srv_id,
                                      service_id_source=source_srv_id,
                                      account_id=account_id)

        sq.task("Validate RS_ID in ConsentForm")
        # Validate RS_ID (RS_ID exists and not used before)
        if self.Helpers.validate_rs_id(_consent_form["source"]["rs_id"]):
            self.Helpers.store_consent_form(_consent_form)  # Store Consent Form
        else:
            raise DetailedHTTPException(title="RS_ID Validation error.",
                                        detail="RS_ID could not be validated.",
                                        status=403)

        sq.send_to("acc", "GET surrogate_id & slr_id")



        # Get slr and surrogate_id
        slr_id_sink, surrogate_id_sink = am.get_surrogate_and_slr_id(account_id, sink_srv_id)
        # One for Sink, one for Source
        slr_id_source, surrogate_id_source = am.get_surrogate_and_slr_id(account_id, source_srv_id)

        sq.reply_from("acc", "surrogate_id & slr_id")

        sq.task("Fetch sink_keys's")

        sink_keys = self.Helpers.get_service_keys(surrogate_id_sink)
        try:
            # TODO: We technically support fetching multiple keys, but use only 1
            sink_key = loads(sink_keys[0])
        except IndexError as e:
            raise DetailedHTTPException(status=500,
                                        title="Fetching service keys for sink has failed.",
                                        detail="Couldn't find keys for surrogate id ({}).".format(surrogate_id_sink),
                                        trace=traceback.format_exc(limit=100).splitlines())
        debug_log.info("Sink keys:\n{}".format(dumps(sink_key, indent=2)))
        sink_pop_key = sink_key["pop_key"]
        # Generate common_cr for both sink and source.
        sq.task("Generate common CR")

        issued = int(time.time()) #datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        # TODO: Not before and not after are Optional. Verify who says when to put them?
        not_before = int(time.time()) #datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        not_after = int(time.time()+current_app.config["NOT_AFTER_INTERVAL"]) #datetime.fromtimestamp(time.time()+current_app.config["NOT_AFTER_INTERVAL"]).strftime("%Y-%m-%dT%H:%M:%SZ")
        operator_id = current_app.config["UID"]

        common_cr_source = self.Helpers.gen_cr_common(surrogate_id_source,
                                                      _consent_form["source"]["rs_id"],
                                                      slr_id_source,
                                                      issued,
                                                      not_before,
                                                      not_after,
                                                      source_srv_id,
                                                      operator_id,
                                                      "Source")

        common_cr_sink = self.Helpers.gen_cr_common(surrogate_id_sink,
                                                    _consent_form["source"]["rs_id"],
                                                    slr_id_sink,
                                                    issued,
                                                    not_before,
                                                    not_after,
                                                    sink_srv_id,
                                                    operator_id,
                                                    "Sink")

        sq.task("Generate ki_cr")
        ki_cr = self.Helpers.Gen_ki_cr(self)  # TODO: Implement

        sq.task("Generate CR for sink")
        sink_cr = self.Helpers.gen_cr_sink(common_cr_sink, _consent_form, ki_cr, common_cr_source["cr_id"])

        sq.task("Generate CR for source")
        source_cr = self.Helpers.gen_cr_source(common_cr_source, _consent_form, ki_cr, sink_pop_key)

        sink_cr["cr"]["common_part"]["rs_description"] = source_cr["cr"]["common_part"]["rs_description"]

        debug_log.info("CR generated for sink:\n{}".format(sink_cr))
        debug_log.info("CR generated for source:\n{}".format(source_cr))
        sq.task("Generate CSR's")

        sink_csr = self.Helpers.gen_csr(surrogate_id_sink, sink_cr["cr"]["common_part"]["cr_id"], "Active",
                                        "null")
        source_csr = self.Helpers.gen_csr(surrogate_id_source, source_cr["cr"]["common_part"]["cr_id"], "Active",
                                          "null")

        sq.send_to("acc", "Send CR/CSR to sign and store")
        result = am.signAndstore(sink_cr, sink_csr, source_cr, source_csr, account_id)
        sq.reply_from("acc", "Signed Sink and Source CR/CSR")

        debug_log.info("CR/CSR structure the Account Manager signed:\n{}".format(dumps(result, indent=2)))
        sink_cr = result["data"]["sink"]["consent_record"]["attributes"]
        sink_csr = result["data"]["sink"]["consent_status_record"]["attributes"]

        source_cr = result["data"]["source"]["consent_record"]["attributes"]
        source_csr = result["data"]["source"]["consent_status_record"]["attributes"]

        crs_csrs_payload = {"sink": {"cr": sink_cr, "csr": sink_csr},
                            "source": {"cr": source_cr, "csr": source_csr}}

        debug_log.info("CR/CSR payload sent to celery task"
                       " for sending to services:\n{}".format(dumps(crs_csrs_payload, indent=2)))
        sq.send_to("SrvMgmtsink", "Post CR-Sink, CSR-Sink")
        sq.send_to("SrvMgmtsource", "Post CR-Source, CSR-Source")
        CR_installer.delay(crs_csrs_payload, self.SH.getService_url(sink_srv_id), self.SH.getService_url(source_srv_id))
        sq.reply_to("OpUi", "Sink & Source cr_id")
        sq.deactivate()
        return {"data":{
                    "attributes": {"sink_cr_id": common_cr_sink["cr_id"], "source_cr_id": common_cr_source["cr_id"]},
                    "type": "ConsentRecordIDs",}
                }, 201

api.add_resource(ConsentFormHandler, '/consent_form/account/<string:account_id>')
