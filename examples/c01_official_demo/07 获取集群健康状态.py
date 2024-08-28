from es6.elasticsearch import Elasticsearch

es = Elasticsearch(
    hosts=["http://192.168.234.130:9200"],
    http_auth=('elastic', 'zhangdapeng520'),
)

# 检查集群健康状态
r = es.cluster.health(wait_for_status='yellow', request_timeout=1)
print(r)
