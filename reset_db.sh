docker-compose kill mysql-db
docker-compose rm --force mysql-db                  # Clean db
docker volume rm mydatasdkbleedingedge_mysql-data   # Clean db
docker-compose up -d mysql-db
