# Deployment
Note: Instructions based on clean Ubuntu 16.04 server


## Prerequisites


### Update system
    sudo apt update
    sudo apt upgrade


### MySQL Database
    sudo apt-get -y install mysql-server-5.7

You will be prompted for prompted to create a root password during the installation. 
These instructions are using 'Y3xUcheg' as root password.


#### Securing MySQL installation
    sudo mysql_secure_installation


#### Finalizing MySQL installation
    sudo service mysql restart


### System wide dependencies with apt
    sudo apt -y install build-essential
    sudo apt -y install libssl-dev
    sudo apt -y install libffi-dev
    sudo apt -y install python
    sudo apt -y install python-dev
    sudo apt -y install python-pip
    sudo apt -y install libmysqlclient-dev
    sudo apt -y install git


### System wide dependencies with pip
    sudo pip install cryptography
    sudo pip install virtualenv


## Deployment


### Development deployment


#### Prepare directories

    cd ~
    mkdir myDataSDK
    cd myDataSDK


#### Clone from Git

    git clone https://github.com/HIIT/mydata-sdk.git
    cd mydata-sdk
    cd Account


#### MySQL Database


##### Start mysql shell

    mysql -u root -pY3xUcheg


##### In MySQL shell

    source ./doc/database/MyDataAccount-DBinit.sql
    source ./doc/database/MyDataAccount-UserInit.sql


##### Quit from MySQL shell

    quit
    

#### Run tests (optional)

    python setup.py test


#### Create virtual environment

    virtualenv venv
    source ./venv/bin/activate
    ./venv/bin/pip install -r requirements.txt


#### Config

Check application configuration file and modify if necessary.

    nano config.py


#### Run

    python run.py


#### Check that application is running

Visit with your web browser at

    127.0.0.1:8080


#### Shutdown

    Ctrl + c
    deactivate
    


### Demo deployment

Before starting make sure that your user belongs to www-data group.


#### Prerequisites

    sudo apt update
    sudo apt -y install nginx
    sudo pip install uwsgi


#### Prepare directories

    sudo mkdir -p /var/www/myDataSDK
    sudo chown -R www-data:www-data /var/www/myDataSDK
    sudo chmod 775 -R /var/www/myDataSDK/
    cd /var/www/myDataSDK/


#### Clone from Git

    git clone https://github.com/HIIT/mydata-sdk.git
    cd mydata-sdk
    cd Account


#### MySQL Database


##### Start mysql shell

    mysql -u root -pY3xUcheg


##### In MySQL shell

    source ./doc/database/MyDataAccount-DBinit.sql
    source ./doc/database/MyDataAccount-UserInit.sql


##### Quit from MySQL shell

    quit
    

#### Run tests (optional)

    python setup.py test


#### Create virtual environment

    virtualenv venv
    source ./venv/bin/activate
    ./venv/bin/pip install -r requirements.txt


#### Config

Check configuration files and modify if necessary.


##### Application Config

    nano config.py


##### uWSGI Config

    nano uwsgi.ini


##### Nginx Config

    nano nginx.conf
    

#### Test uWSGI serving


##### Test that uWSGI serving is working properly

    sudo uwsgi --socket 0.0.0.0:8080 --protocol=http -w wsgi --virtualenv venv/ --callable app

Try to access application with web-browser via your domain. For example http://example.org:8080


##### Kill uWSGI process

    Ctrl + c


##### Deactivate virtual environment

    deactivate


#### Start uWSGI serving

Alternatively you can write upstart script that starts uWSGI serving at system startup.

    sudo uwsgi --ini uwsgi.ini &

#### Configure Nginx


##### Delete default config

    sudo rm /etc/nginx/sites-enabled/default
    sudo rm /etc/nginx/sites-available/default


##### Add new configuration file

    sudo cp nginx.conf /etc/nginx/sites-available/mydata-account


#### Enable new site

    sudo ln -s /etc/nginx/sites-available/mydata-account /etc/nginx/sites-enabled/mydata-account


#### Check Nginx config for syntax errors

    sudo nginx -t


#### Restart Nginx

    sudo service nginx restart


#### Access Account

Access application with web-browser via (http://example.org:80)

