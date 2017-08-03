# -*- coding: utf-8 -*-
__author__ = 'alpaloma'
import logging
import time
from json import loads, dumps

from flask import request, Blueprint, current_app, render_template_string, make_response, redirect
from flask_cors import CORS
from flask_restful import Resource, Api, reqparse
from jwcrypto import jwk
from requests import post

from base64 import urlsafe_b64encode as encode64
from base64 import urlsafe_b64decode as decode64

from uuid import uuid4 as guid
from DetailedHTTPException import DetailedHTTPException, error_handler
from helpers_op import Helpers, format_request


debug_log = logging.getLogger("debug")

api_operator_ui_blueprint = Blueprint("api_service_ui_blueprint", __name__)

CORS(api_operator_ui_blueprint)
api = Api()
api.init_app(api_operator_ui_blueprint)

from functools import wraps
from flask import request, Response



class LinkingUi(Resource):
    def __init__(self):
        super(LinkingUi, self).__init__()
        self.helpers = Helpers(current_app.config)
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('surrogate_id', type=str, help='Surrogate_id from a service.')
        self.parser.add_argument('service_id', type=str, help='ID of linking service.')
        self.parser.add_argument('return_url', type=str, help='Url safe Base64 coded return url.')
        self.parser.add_argument('linkingFrom', type=str, help='Origin of the linking request(?)')

    @error_handler
    def get(self):
        debug_log.info(format_request(request))
        args = self.parser.parse_args()

        # Check headers for Account API key

        # If key is n


        # TODO: Use template file or get this from somewhere.
        tmpl_str = '''
        <html><header></header><body>
                    <form class="form-horizontal" action="" method="POST">
              <fieldset>
                <legend>Link {{provider}} with Operator({{ operator_id }})</legend>
                <div class="form-group">
                  <div class="col-lg-10 col-lg-offset-1">
                    <button type="reset" class="btn btn-default">Cancel</button>
                    <button type="submit" class="btn btn-primary">Submit</button>
                  </div>
                </div>
              </fieldset>
              <div {{ fromOperator }}>
                <p> By linking service to Operator, you agree to the <a href="#LinkToToS">Terms of Service</a></p>
              </div>
              <input type="hidden" name="surrogate_id" value="{{ surrogate_id }}">
              <input type="hidden" name="service_id" value="{{ service_id }}">
              <input type="hidden" name="return_url" value="{{ return_url }}">
              <input type="hidden" name="linkingFrom" value="{{ linkingFrom }}">
            </form>
        </body></html>
        '''
        # Render Login template
        response = make_response(render_template_string(tmpl_str, **args), 200)
        return response

    def post(self):
        debug_log.info(format_request(request))
        args = self.parser.parse_args()


api.add_resource(LinkingUi, '/linking_service')