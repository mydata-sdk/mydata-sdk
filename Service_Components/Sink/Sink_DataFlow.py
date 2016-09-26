# -*- coding: utf-8 -*-
__author__ = 'alpaloma'

from flask import Blueprint, make_response
from flask_restful import Resource, Api
from DetailedHTTPException import DetailedHTTPException, error_handler

api_Sink_blueprint = Blueprint("api_Sink_blueprint", __name__)
api = Api()
api.init_app(api_Sink_blueprint)


# import xmltodict
# @api.representation('application/xml')
# def output_xml(data, code, headers=None):
#     if isinstance(data, dict):
#         xm = {"response": data}
#         resp = make_response(xmltodict.unparse(xm, pretty=True), code)
#         resp.headers.extend(headers)
#         return resp

class DataFlow(Resource):
    @error_handler
    def get(self):
        status = {"status": "running", "service_mode": "Sink"}
        return status


api.add_resource(DataFlow, '/init')

