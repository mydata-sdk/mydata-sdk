# -*- coding: utf-8 -*-

# Import dependencies
import urllib

from flask import Blueprint
from flask import current_app
from flask import json
from flask import url_for
from flask_restful import Resource, Api
import requests

# Import Models
from werkzeug.routing import BaseConverter

from app.helpers import get_custom_logger, ApiError, make_json_response

# Define the blueprint: 'auth', set its url prefix: app.url/auth
from app.mod_system.controller import clear_mysql_db, clear_blackbox_db, clear_api_key_db, system_check

mod_system = Blueprint('system', __name__, template_folder='templates')
api = Api(mod_system)

# create logger
logger = get_custom_logger(__name__)


class ClearDb(Resource):
    def get(self):
        """
        Clear Database content
        :return:
        """

        # Response data container
        response_data = {}

        # Clear MySQL Database
        logger.info("Clearing MySQL Database")
        try:
            clear_mysql_db()
        except Exception as exp:
            logger.error("Could not clear MySQL Database: " + repr(exp))
            raise ApiError(code=500, title="Could not clear MySQL Database", detail=repr(exp))
        else:
            logger.info("MySQL Database cleared")
            response_data['Account'] = "MySQL Database cleared"

        # Clear Blackbox Database
        logger.info("Clearing Blackbox Database")
        try:
            clear_blackbox_db()
        except Exception as exp:
            logger.error("Could not clear Blackbox Database: " + repr(exp))
            raise ApiError(code=500, title="Could not clear Blackbox Database", detail=repr(exp))
        else:
            logger.info("Blackbox Database cleared")
            response_data['Blackbox'] = "Blackbox Database cleared"

        # Clear ApiKey Database
        logger.info("Clearing ApiKey Database")
        try:
            clear_api_key_db()
        except Exception as exp:
            logger.error("Could not clear ApiKey Database: " + repr(exp))
            raise ApiError(code=500, title="Could not clear ApiKey Database", detail=repr(exp))
        else:
            logger.info("ApiKey Database cleared")
            response_data['ApiKey'] = "ApiKey Database cleared"

        # Response
        return make_json_response(data=response_data, status_code=200)


class SystemStatus(Resource):
    def get(self):
        """
        Status check
        :param:
        :return:
        """

        logger.info("Checking system status")
        try:
            response_data_dict = system_check()
        except Exception as exp:
            error_title = "API seems to be working fine, but database connection might be down."
            error_detail = repr(exp)
            logger.error(error_title + " - " + error_detail)
            raise ApiError(code=500, title=error_title, detail=error_detail)
        else:
            logger.info("System running as intended")

        # Response
        logger.info(json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class SystemRunning(Resource):
    def get(self):
        """
        Status check
        :param:
        :return:
        """

        logger.info("Checking API status")
        logger.info("API running as intended")

        # Response
        response_data_dict = {"status": "running"}
        logger.info(json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)


class SystemRoutes(Resource):
    def get(self):
        """
        Application routes
        :param secret:
        :return:
        """

        # Routes to list
        # http://flask.pocoo.org/snippets/117/
        routes = []
        for rule in current_app.url_map.iter_rules():
            options = {}
            for arg in rule.arguments:
                options[arg] = "[{0}]".format(arg)

            url = url_for(rule.endpoint, **options)
            pretty_url = urllib.unquote("{}".format(url))

            route = {
                "url": pretty_url,
                "methods": ','.join(rule.methods)
            }
            routes.append(route)

        # Response
        response_data_dict = {'routes': routes}
        logger.info(json.dumps(response_data_dict))
        return make_json_response(data=response_data_dict, status_code=200)

# Register resources
api.add_resource(ClearDb, '/system/db/clear/', endpoint='db_clear')
api.add_resource(SystemStatus, '/system/status/', endpoint='system_status')
api.add_resource(SystemRunning, '/', endpoint='system_running')
api.add_resource(SystemRoutes, '/system/routes/', endpoint='system_routes')
