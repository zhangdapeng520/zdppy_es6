import os
from .new import new


def new_env():
    """
    新建ES6客户端连接对象
    """
    # 从环境变量读取参数
    host = os.environ.get("ZDPPY_ES6_HOST", "127.0.0.1")
    port = os.environ.get("ZDPPY_ES6_PORT", "9200")
    username = os.environ.get("ZDPPY_ES6_USERNAME", "elastic")
    password = os.environ.get("ZDPPY_ES6_PASSWORD", "zhangdapeng520")

    return new(host, port, username, password)
