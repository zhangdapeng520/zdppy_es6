from es6.elasticsearch import Elasticsearch

es = Elasticsearch(
    hosts=["http://192.168.234.130:9200"],
    http_auth=('elastic', 'zhangdapeng520'),
)

# 创建索引：忽略400索引已存在错误
es.indices.create(index='test-index', ignore=400)

# 删除索引：忽略400异常和404索引不存在错误
es.indices.delete(index='test-index', ignore=[400, 404])
