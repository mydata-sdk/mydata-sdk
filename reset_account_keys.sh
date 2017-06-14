docker-compose rm --force mysql-db			# Clean MySql container
docker volume rm mydatasdkbleedingedge_mysql-data	# Clean MySql db
docker-compose rm --force account			# Clean Account container
docker volume rm mydatasdkbleedingedge_account-key-data	# Clean Account SQL

