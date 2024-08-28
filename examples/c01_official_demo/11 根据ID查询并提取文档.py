from datetime import datetime
from es6.elasticsearch import Elasticsearch

es = Elasticsearch(
    hosts=["http://192.168.234.130:9200"],
    http_auth=('elastic', 'zhangdapeng520'),
)

# 创建索引
index = "test-index"
doc_type = 'tweet'
doc = {
    'author': 'kimchy',
    'text': 'Elasticsearch: cool. bonsai cool.',
    'timestamp': datetime.now(),
}
res = es.index(index=index, doc_type=doc_type, id=1, body=doc, ignore=400)
print(res['result'])

# 根据ID查询并提取文档
print(es.get_source(index, doc_type, 1))

# 删除索引
es.indices.delete(index='test-index', ignore=[400, 404])
