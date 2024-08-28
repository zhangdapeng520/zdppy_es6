from es6.elasticsearch import Elasticsearch

es = Elasticsearch(
    hosts=["http://192.168.234.130:9200"],
    http_auth=('elastic', 'zhangdapeng520'),
)
print(es.ping())