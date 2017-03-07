# -*- coding: utf-8 -*-

"""
__author__ = "Jani Yli-Kantola"
__copyright__ = ""
__credits__ = ["Harri Hirvonsalo", "Aleksi Palomäki"]
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Jani Yli-Kantola"
__contact__ = "https://github.com/HIIT/mydata-stack"
__status__ = "Development"
"""

import sys
reload(sys)
sys.setdefaultencoding('utf-8')


def create_app(config_filename='config'):
    from flask import Flask, json, current_app
    from flask_restful import Api
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

        # add prefix here or it won't work when you register blueprint
        #api = Api(current_app, prefix=current_app.config["URL_PREFIX"])

        # Before each request
        @current_app.before_request
        def new_request():
            print("New Request")
            print("############")

        # Error Handlers
        @current_app.errorhandler(404)
        def not_found(error):
            not_found_error = ApiError(code=404, title="Not Found", detail="Endpoint not found", status="NotFound")
            error_dict = not_found_error.to_dict()
            return make_json_response(errors=error_dict, status_code=str(error_dict['code']))

        @current_app.errorhandler(ApiError)
        def handle_apierror(error):
            error_dict = error.to_dict()
            logger = get_custom_logger(logger_name="ApiError")
            logger.error(json.dumps(error_dict))
            return make_json_response(errors=error_dict, status_code=str(error_dict['code']))

        # Import a module / component using its blueprint handler variable
        from app.mod_auth.controllers import mod_auth
        from app.mod_api_auth.view_api import mod_api_auth
        from app.mod_account.view_html import mod_account_html
        from app.mod_account.view_api import mod_account_api
        from app.mod_service.view_api import mod_service_api
        from app.mod_authorization.view_api import mod_authorization_api
        from app.mod_system.controllers import mod_system

        # Register blueprint(s)
        current_app.register_blueprint(mod_auth)
        current_app.register_blueprint(mod_api_auth)
        current_app.register_blueprint(mod_account_html)
        current_app.register_blueprint(mod_account_api)
        current_app.register_blueprint(mod_service_api)
        current_app.register_blueprint(mod_system)
        current_app.register_blueprint(mod_authorization_api)

        # Print URL map
        print current_app.url_map

    return app

