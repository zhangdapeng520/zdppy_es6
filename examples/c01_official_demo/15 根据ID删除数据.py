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

# 根据ID删除文档
doc = {
    "doc": {
        'author': '张大鹏',
        'text': 'Elasticsearch: cool. bonsai cool.',
        'timestamp': datetime.now(),
    }
}
es.delete(index, doc_type, 1)
es.indices.refresh(index=index)

# 查询所有数据
res = es.search(index=index, body={"query": {"match_all": {}}})
print("Got %d Hits:" % res['hits']['total'])
for hit in res['hits']['hits']:
    print("%(timestamp)s %(author)s: %(text)s" % hit["_source"])

# 删除索引
es.indices.delete(index='test-index', ignore=[400, 404])
