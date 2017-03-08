# -*- coding: utf-8 -*-

# Import dependencies
from flask import Blueprint
from flask_restful import Resource, Api
import requests

# Import Models
from app.helpers import get_custom_logger, ApiError, make_json_response

# Define the blueprint: 'auth', set its url prefix: app.url/auth
from app.mod_system.controller import clear_mysql_db, clear_blackbox_db, clear_api_key_db

mod_system = Blueprint('system', __name__, template_folder='templates')
api = Api(mod_system)

# create logger
logger = get_custom_logger(__name__)


class ClearDb(Resource):
    def get(self, secret=None):
        """
        Clear Database content
        :param secret:
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
        response_data_dict = {'status': 'DB cleared'}
        return make_json_response(data=response_data_dict, status_code=200)


# Register resources
api.add_resource(ClearDb, '/system/db/clear/', endpoint='db_clear')
