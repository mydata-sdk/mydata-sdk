---

# MyData SDK Components
This is a part of MyData-SDK implementation of MyData Architecture.


Components are split to their own folders

- [ MyData Account ](/Account/)
- [ Operator Components ](/Operator_Components/)
- [ Service Components ](/Service_Components/)
- [ Service Mockup ](/Service_Mockup/)


## Version
2.0 beta release, final release will be made in September 2017

## Prerequisites
- [Flask](http://flask.pocoo.org/)
- [Flask-RESTful](http://flask-restful.readthedocs.org/)

## Simple Consent-flow demo

Note:
These instructions have been tested with Linux.
You need to have [Docker](https://www.docker.com/products/overview#/install_the_platform), [Docker Compose](https://docs.docker.com/compose/), [Python](https://www.python.org/) and [Requests -library](http://docs.python-requests.org/) for Python installed.

Clone the repo and start the Docker Compose stack:
```
cd mydata-sdk
sudo sh start.sh  # Needed to run root only if you haven't configured a docker group for your system
```

Wait until Docker Compose stack has properly started. Last message should be similar to
```
mysql-db                  | Version: '5.7.19'  socket: '/var/run/mysqld/mysqld.sock'  port: 3306  MySQL Community Server (GPL)
```

Now open another terminal and run the ui_flow_local.py
```
python ui_flow_local.py --skip_data
```

### Known issues

Note that data transfer is currently not working. 

## Deployment

Deployment instructions for each component can be found from module's documentation.

## Specifications

[MyData Architecture](https://github.com/mydata-sdk/mydata-docs)


## Contributing/Contact

- Via GitHub issues
- Contact: Harri Honko (harri.honko@tut.fi) or Antti Poikola (antti.poikola@hiit.fi)


## Copying and License
This code is licensed under [MIT License](LICENSE)
