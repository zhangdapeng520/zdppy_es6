from es6.elasticsearch import Elasticsearch


def new(
        host="127.0.0.1",
        port=9200,
        username="elastic",
        password="zhangdapeng520",
):
    """
    新建ES6客户端连接对象
    """
    return Elasticsearch(
        hosts=[f"http://{host}:{port}"],
        http_auth=(username, password),
    )
