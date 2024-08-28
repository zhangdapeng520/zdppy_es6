from datetime import datetime
from es6.elasticsearch import Elasticsearch

es = Elasticsearch(
    hosts=["http://192.168.234.130:9200"],
    http_auth=('elastic', 'zhangdapeng520'),
)

# 新增
doc = {
    'author': 'kimchy',
    'text': 'Elasticsearch: cool. bonsai cool.',
    'timestamp': datetime.now(),
}
es.index(index="test-index", doc_type='tweet', id=1, body=doc)
es.indices.refresh(index="test-index")

# 查询并过滤
res = es.search(
    index="test-index",
    body={"query": {"match_all": {}}},
    filter_path=['hits.hits._id', 'hits.hits._type'],
)
print(res)
