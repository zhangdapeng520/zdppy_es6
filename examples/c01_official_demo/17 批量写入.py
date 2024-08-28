from es6.elasticsearch import Elasticsearch

es = Elasticsearch(
    hosts=["http://192.168.234.130:9200"],
    http_auth=("elastic", "zhangdapeng520"),
)

# 创建索引
index = "user"
mappings = {
    "settings": {
        "number_of_shards": 1
    },
    "mappings": {
        "user": {
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "text"},
                "age": {"type": "integer"},
            }
        }
    }
}
es.indices.create(index, mappings, ignore=[400])

# 批量添加
data = [
    {"index": {"_index": index, "_type": index, "_id": "1"}},
    {"id": "1", "name": "张三1", "age": 21},
    {"index": {"_index": index, "_type": index, "_id": "2"}},
    {"id": "1", "name": "张三2", "age": 22},
    {"index": {"_index": index, "_type": index, "_id": "3"}},
    {"id": "1", "name": "张三3", "age": 23},
]
es.bulk(data)
es.indices.refresh(index=index)

# 查询
r = es.search(index)
print(r["hits"]["hits"])

# 删除索引
es.indices.delete(index)
