# -*- coding: utf-8 -*-

"""
__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "1.3.0"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

import sys

from flask import request

reload(sys)
sys.setdefaultencoding('utf-8')


def create_app(config_filename='config'):
    """
    Application Factory
    :param config_filename:
    :return: Application object
    """
    from flask import Flask, json, current_app
    from app.helpers import ApiError, make_json_response, get_custom_logger
    from app.app_modules import db, login_manager

    # Application object
    app = Flask(__name__)
    with app.app_context():
        current_app.config.from_object(config_filename)

        # Database
        db.init_app(current_app)

        # LoginManager
        login_manager.init_app(app)
        login_manager.login_view = current_app.config["LOGIN_VIEW"]
        login_manager.login_message = current_app.config["LOGIN_MESSAGE"]
        login_manager.session_protection = current_app.config["SESSION_PROTECTION"]
        # TODO: Validate next()

        # Before each request
        @current_app.before_request
        def new_request():
            print("New Request: " + str(request.path))
            print("############")

        # Error Handlers
        @current_app.errorhandler(404)
        def not_found(error):
            try:
                request_url = request.path
            except Exception as exp:
                request_url = "Unknown"
            not_found_error = ApiError(code=404, title="Not Found", detail="Endpoint not found", status="NotFound", source=request_url)
            error_dict = not_found_error.to_dict()
            return make_json_response(errors=error_dict, status_code=str(error_dict['code']))

        @current_app.errorhandler(ApiError)
        def handle_apierror(error):
            error_dict = error.to_dict()
            logger = get_custom_logger(logger_name="ApiError")
            logger.error(json.dumps(error_dict))
            return make_json_response(errors=error_dict, status_code=str(error_dict['code']))

        # Import a module / component using its blueprint handler variable
        from app.mod_api_auth.view_api import mod_api_auth
        from app.mod_account.view_api import mod_account_api
        from app.mod_service.view_api import mod_service_api
        from app.mod_authorization.view_api import mod_authorization_api
        from app.mod_system.view_api import mod_system

        # URL Prefixs
        prefix_api_auth = current_app.config["BLUEPRINT_URL_PREFIX"]
        prefix_api_account = current_app.config["BLUEPRINT_URL_PREFIX"] + "/" + "external"
        prefix_api_service = current_app.config["BLUEPRINT_URL_PREFIX"] + "/" + "internal"
        prefix_api_authorization = current_app.config["BLUEPRINT_URL_PREFIX"] + "/" + "internal"
        prefix_api_system = current_app.config["BLUEPRINT_URL_PREFIX"] + "/" + "internal"

        # Register blueprint(s)
        current_app.register_blueprint(mod_api_auth, url_prefix=prefix_api_auth)
        current_app.register_blueprint(mod_account_api, url_prefix=prefix_api_account)
        current_app.register_blueprint(mod_service_api, url_prefix=prefix_api_service)
        current_app.register_blueprint(mod_system, url_prefix=prefix_api_system)
        current_app.register_blueprint(mod_authorization_api, url_prefix=prefix_api_authorization)

        print("Running..")

    return app

