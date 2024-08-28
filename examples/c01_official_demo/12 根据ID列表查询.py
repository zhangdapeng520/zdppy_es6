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
es.index(index=index, doc_type=doc_type, id=1, body=doc, ignore=400)
es.index(index=index, doc_type=doc_type, id=2, body=doc, ignore=400)

# 根据ID列表查询
body = {
    "docs": [
        {
            "_index": index,
            "_id": 1
        },
        {
            "_index": index,
            "_id": 2
        },
    ]
}
print(es.mget(body, index))

# 删除索引
es.indices.delete(index='test-index', ignore=[400, 404])
