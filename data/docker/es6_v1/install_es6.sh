docker pull elasticsearch:6.8.23
mkdir -p /docker/elasticsearch/config
cp ./elasticsearch.yml /docker/elasticsearch/config/
docker run -itd --name elasticsearch -p 9200:9200 -v /docker/elasticsearch/config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -e "discovery.type=single-node" -e ES_JAVA_OPTS="-Xms2g -Xmx2g" -e ELASTIC_PASSWORD=zhangdapeng520 elasticsearch:6.8.23
docker logs -f --tail 100 e