docker-compose kill operator_components
docker-compose rm --force operator_components       # Clean db
#docker volume rm mydatasdkbleedingedge_mysql-data  # Clean db
docker-compose up -d operator_components
