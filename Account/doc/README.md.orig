# MyData Account - Documentation

## High level prerequisites
- [MySQL 5.7](https://www.mysql.com/)
- [SQLite](https://www.sqlite.org/)
- [Python 2.7](https://www.python.org/download/releases/2.7/)
- [Flask](http://flask.pocoo.org/)
- [Flask-RESTful](http://flask-restful.readthedocs.io)
- [JWCrypto](https://jwcrypto.readthedocs.io/en/stable/)

## Detailed Documentation
- [Deployment](deployment.md)
- [API documentation](api/)
- [Database documentation](database/)
- [Developer one-liners](developer_oneliners.md)


## Application Modules

### Account module
Account module (mod_account) provides implementation to fulfill requirements of external API that provides APIs for front-end applications.

### Service Linking module
Service module (mod_service) provides implementation to fulfill requirements of MyData Service Linking Specification.

### Authorization module
Authorization module (mod_mod_authorization) provides implementation to fulfill requirements of MyData Authorization Specification.

### Key Management module
Key Management module (mod_blackbox) provides key management services for MyData Account. This module is meant only for demonstration purposes. Module does not provide a secure key store.
Uses SQLite database to provide separate data location.

### Database module
Database module (mod_database) provides database integration for MyData Account.

### System module
System module (mod_system) provides system health checks.

### Authentication module
Authentication modules (mod_auth and mod_api_auth) provide authentication logic for APIs.
Uses SQLite database to provide separate data location.

### Tests

Test cases for MyData Account can be found from [tests directory](../app/tests)

- SdkTestCase class (in file test_sdk.py) provides test cases for Internal API
- UiTestCase class (in file test_ui.py) provides test cases for External API

#### Test coverage reports

Coverage reports for existing test cases can be found from [coverage-reports directory](../app/tests/coverage-reports)

#### Running the tests

Instructions to run test cases can be found from [deployment instructions](deployment.md)

## Architecture
High level description of MyData Account Architecture

![Architecture](images/MyDataAccount_Architecture.png)
