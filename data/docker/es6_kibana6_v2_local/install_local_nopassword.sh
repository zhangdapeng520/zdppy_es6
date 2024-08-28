ip=192.168.234.129
version=6.8.23

echo "安装es6"
docker stop es6 && docker rm es6
docker run -itd --name es6 -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e ES_JAVA_OPTS="-Xms2g -Xmx2g" \
  elasticsearch:${version}

echo "安装kibana"
docker stop es6kbn && docker rm es6kbn
docker run -itd --name es6kbn \
  -e ELASTICSEARCH_URL=http://${ip}:9200 \
  -p 5601:5601 kibana:${version}
echo "安装kibana成功，请访问：http://localhost:5601"