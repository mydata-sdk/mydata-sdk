mkdir -p ./init-db
cp ./Account/doc/database/MyDataAccount-DBinit.sql ./init-db/
cp ./Account/doc/database/MyDataAccount-UserInit.sql ./init-db/
cp ./Operator_Components/doc/database/Operator_Components-DBinit.sql ./init-db/
cp ./Service_Components/doc/database/Service_Components-DBinit-Sink.sql ./init-db/
cp ./Service_Components/doc/database/Service_Components-DBinit-Source.sql ./init-db/
cp ./Service_Mockup/doc/database/Service_Mockup-DBinit_Sink.sql ./init-db/
cp ./Service_Mockup/doc/database/Service_Mockup-DBinit_Source.sql ./init-db/
sh reset_db.sh
#docker-compose rm --force mysql-db                  # Clean db
#docker volume rm mydatasdkbleedingedge_mysql-data   # Clean MySql db
#docker volume rm mydatasdkbleedingedge_redis-data   # Clean Redis db
reset                                               # Reset terminal
docker-compose down --remove-orphans                # Clean out trash.
docker-compose up --build                           # Put the thing up and running

