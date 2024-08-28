ip=192.168.234.129
version=6.8.23

echo "准备配置文件"
mkdir -p /docker/es6kbna/config
cp ./elasticsearch.yml /docker/es6kbna/config/
cp ./kibana.yml /docker/es6kbna/config/

echo "安装es6"
docker stop es6 && docker rm es6
docker run -itd --name es6 -p 9200:9200 \
  -v /docker/es6kbna/config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml \
  -e "discovery.type=single-node" \
  -e ES_JAVA_OPTS="-Xms2g -Xmx2g" \
  -e ELASTIC_PASSWORD=zhangdapeng520 \
  elasticsearch:${version}

echo "安装kibana"
docker stop es6kbn && docker rm es6kbn
docker run -itd --name es6kbn \
  -v /docker/es6kbna/config/kibana.yml:/usr/share/kibana/config/kibana.yml \
  -e ELASTICSEARCH_URL=http://${ip}:9200 \
  -p 5601:5601 kibana:${version}
echo "安装kibana成功，请访问：http://localhost:5601"
docker logs -f --tail 100 es6kbn