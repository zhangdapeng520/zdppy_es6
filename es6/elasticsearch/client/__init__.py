from __future__ import unicode_literals
import logging

from ..transport import Transport
from ..exceptions import TransportError
from ..compat import string_types, urlparse, unquote
from .indices import IndicesClient
from .ingest import IngestClient
from .cluster import ClusterClient
from .cat import CatClient
from .nodes import NodesClient
from .remote import RemoteClient
from .snapshot import SnapshotClient
from .tasks import TasksClient
from .utils import query_params, _make_path, SKIP_IN_PATH

logger = logging.getLogger('elasticsearch')


def _normalize_hosts(hosts):
    """
    Helper function to transform hosts argument to
    :class:`~elasticsearch.Elasticsearch` to a list of dicts.
    """
    # if hosts are empty, just defer to defaults down the line
    if hosts is None:
        return [{}]

    # passed in just one string
    if isinstance(hosts, string_types):
        hosts = [hosts]

    out = []
    # normalize hosts to dicts
    for host in hosts:
        if isinstance(host, string_types):
            if '://' not in host:
                host = "//%s" % host

            parsed_url = urlparse(host)
            h = {"host": parsed_url.hostname}

            if parsed_url.port:
                h["port"] = parsed_url.port

            if parsed_url.scheme == "https":
                h['port'] = parsed_url.port or 443
                h['use_ssl'] = True

            if parsed_url.username or parsed_url.password:
                h['http_auth'] = '%s:%s' % (unquote(parsed_url.username),
                                            unquote(parsed_url.password))

            if parsed_url.path and parsed_url.path != '/':
                h['url_prefix'] = parsed_url.path

            out.append(h)
        else:
            out.append(host)
    return out


class Elasticsearch(object):
    """
    Elasticsearch low-level client. Provides a straightforward mapping from
    Python to ES REST endpoints.

    The instance has attributes ``cat``, ``cluster``, ``indices``, ``ingest``,
    ``nodes``, ``snapshot`` and ``tasks`` that provide access to instances of
    :class:`~elasticsearch.client.CatClient`,
    :class:`~elasticsearch.client.ClusterClient`,
    :class:`~elasticsearch.client.IndicesClient`,
    :class:`~elasticsearch.client.IngestClient`,
    :class:`~elasticsearch.client.NodesClient`,
    :class:`~elasticsearch.client.SnapshotClient` and
    :class:`~elasticsearch.client.TasksClient` respectively. This is the
    preferred (and only supported) way to get access to those classes and their
    methods.

    You can specify your own connection class which should be used by providing
    the ``connection_class`` parameter::

        # create connection to localhost using the ThriftConnection
        es = Elasticsearch(connection_class=ThriftConnection)

    If you want to turn on :ref:`sniffing` you have several options (described
    in :class:`~elasticsearch.Transport`)::

        # create connection that will automatically inspect the cluster to get
        # the list of active nodes. Start with nodes running on 'esnode1' and
        # 'esnode2'
        es = Elasticsearch(
            ['esnode1', 'esnode2'],
            # sniff before doing anything
            sniff_on_start=True,
            # refresh nodes after a node fails to respond
            sniff_on_connection_fail=True,
            # and also every 60 seconds
            sniffer_timeout=60
        )

    Different hosts can have different parameters, use a dictionary per node to
    specify those::

        # connect to localhost directly and another node using SSL on port 443
        # and an url_prefix. Note that ``port`` needs to be an int.
        es = Elasticsearch([
            {'host': 'localhost'},
            {'host': 'othernode', 'port': 443, 'url_prefix': 'es', 'use_ssl': True},
        ])

    If using SSL, there are several parameters that control how we deal with
    certificates (see :class:`~elasticsearch.Urllib3HttpConnection` for
    detailed description of the options)::

        es = Elasticsearch(
            ['localhost:443', 'other_host:443'],
            # turn on SSL
            use_ssl=True,
            # make sure we verify SSL certificates (off by default)
            verify_certs=True,
            # provide a path to CA certs on disk
            ca_certs='/path/to/CA_certs'
        )

    SSL client authentication is supported
    (see :class:`~elasticsearch.Urllib3HttpConnection` for
    detailed description of the options)::

        es = Elasticsearch(
            ['localhost:443', 'other_host:443'],
            # turn on SSL
            use_ssl=True,
            # make sure we verify SSL certificates (off by default)
            verify_certs=True,
            # provide a path to CA certs on disk
            ca_certs='/path/to/CA_certs',
            # PEM formatted SSL client certificate
            client_cert='/path/to/clientcert.pem',
            # PEM formatted SSL client key
            client_key='/path/to/clientkey.pem'
        )

    Alternatively you can use RFC-1738 formatted URLs, as long as they are not
    in conflict with other options::

        es = Elasticsearch(
            [
                'http://user:secret@localhost:9200/',
                'https://user:secret@other_host:443/production'
            ],
            verify_certs=True
        )

    """

    def __init__(self, hosts=None, transport_class=Transport, **kwargs):
        """
        :arg hosts: list of nodes we should connect to. Node should be a
            dictionary ({"host": "localhost", "port": 9200}), the entire dictionary
            will be passed to the :class:`~elasticsearch.Connection` class as
            kwargs, or a string in the format of ``host[:port]`` which will be
            translated to a dictionary automatically.  If no value is given the
            :class:`~elasticsearch.Urllib3HttpConnection` class defaults will be used.

        :arg transport_class: :class:`~elasticsearch.Transport` subclass to use.

        :arg kwargs: any additional arguments will be passed on to the
            :class:`~elasticsearch.Transport` class and, subsequently, to the
            :class:`~elasticsearch.Connection` instances.
        """
        self.transport = transport_class(_normalize_hosts(hosts), **kwargs)

        # namespaced clients for compatibility with API names
        self.indices = IndicesClient(self)
        self.ingest = IngestClient(self)
        self.cluster = ClusterClient(self)
        self.cat = CatClient(self)
        self.nodes = NodesClient(self)
        self.remote = RemoteClient(self)
        self.snapshot = SnapshotClient(self)
        self.tasks = TasksClient(self)

    def __repr__(self):
        try:
            # get a lost of all connections
            cons = self.transport.hosts
            # truncate to 10 if there are too many
            if len(cons) > 5:
                cons = cons[:5] + ['...']
            return '<Elasticsearch(%r)>' % cons
        except:
            # probably operating on custom transport and connection_pool, ignore
            return super(Elasticsearch, self).__repr__()

    def _bulk_body(self, body):
        # if not passed in a string, serialize items and join by newline
        if not isinstance(body, string_types):
            body = '\n'.join(map(self.transport.serializer.dumps, body))

        # bulk body must end with a newline
        if not body.endswith('\n'):
            body += '\n'

        return body

    @query_params()
    def ping(self, params=None):
        """
        如果群集已启动，则返回 True，否则返回 False。
        `<http://www.elastic.co/guide/>`_
        """
        try:
            return self.transport.perform_request('HEAD', '/', params=params)
        except TransportError:
            return False

    @query_params()
    def info(self, params=None):
        """
        Get the basic info from the current cluster.
        `<http://www.elastic.co/guide/>`_
        """
        return self.transport.perform_request('GET', '/', params=params)

    @query_params('parent', 'pipeline', 'refresh', 'routing', 'timeout',
                  'timestamp', 'ttl', 'version', 'version_type', 'wait_for_active_shards')
    def create(self, index, doc_type, id, body, params=None):
        """
        Adds a typed JSON document in a specific index, making it searchable.
        Behind the scenes this method calls index(..., op_type='create')
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html>`_

        :arg index: 索引名称
        :arg doc_type: The type of the document
        :arg id: 文档ID
        :arg body: The document
        :arg parent: ID of the parent document
        :arg pipeline: The pipeline id to preprocess incoming documents with
        :arg refresh: If `true` then refresh the affected shards to make this
            operation visible to search, if `wait_for` then wait for a refresh
            to make this operation visible to search, if `false` (the default)
            then do nothing with refreshes., valid choices are: 'true', 'false',
            'wait_for'
        :arg routing: 特定路由值
        :arg timeout: 显式操作超时
        :arg timestamp: 文件的明确时间戳
        :arg ttl: 文件失效时间
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 "internal"、"external"、"external_gte"、"force"
        :arg wait_for_active_shards: Sets the number of shard copies that must
            be active before proceeding with the index operation. Defaults to 1,
            meaning the primary shard only. Set to `all` for all shard copies,
            otherwise set to any non-negative value less than or equal to the
            total number of copies for the shard (number of replicas + 1)
        """
        for param in (index, doc_type, id, body):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('PUT', _make_path(index, doc_type,
                                                                id, '_create'), params=params, body=body)

    @query_params('op_type', 'parent', 'pipeline', 'refresh', 'routing',
                  'timeout', 'timestamp', 'ttl', 'version', 'version_type',
                  'wait_for_active_shards')
    def index(self, index, doc_type, body, id=None, params=None):
        """
        在特定索引中添加或更新类型化JSON文档，使其可搜索。
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html>`_

        :arg index: 索引名称
        :arg doc_type: 文档类型
        :arg body: 文档内容
        :arg id: 文档ID
        :arg op_type: 显式操作类型，默认为'index'，有效选项为:'index'， 'create'
        :arg parent: 父文档ID
        :arg pipeline: 用于预处理传入文档的管道id
        :arg refresh: 如果为“true”，则刷新受影响的分片以使此操作对搜索可见，如果为“wait_for”，则等待刷新以使此操作对搜索可见，如果为“false”(默认值)，则不做任何刷新。，有效的选择是:'true'， 'false'， 'wait_for'
        :arg routing: 指定路由值
        :arg timeout: 执行超时时间
        :arg timestamp: 文档的显式时间戳
        :arg ttl: 文件失效时间
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 内部"、"外部"、"external_gte"、"强制
        :arg wait_for_active_shards: 设置在进行索引操作前必须激活的分区副本数量。默认设置为 1，表示仅主分区处于活动状态。设置为 "all "表示所有分区副本，否则设置为任何小于或等于分区副本总数（副本数 + 1）的非负值。
        """
        for param in (index, doc_type, body):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('POST' if id in SKIP_IN_PATH else 'PUT',
                                              _make_path(index, doc_type, id), params=params, body=body)

    @query_params('_source', '_source_exclude', '_source_include', 'parent',
                  'preference', 'realtime', 'refresh', 'routing', 'stored_fields',
                  'version', 'version_type')
    def exists(self, index, doc_type, id, params=None):
        """
        返回一个布尔值，表示给定文档是否存在于 Elasticsearch 中。
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html>`_

        :arg index: 索引名称
        :arg doc_type: 文件类型（使用 `_all`获取所有类型中第一个与 ID 匹配的文件）
        :arg id: 文档 ID
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include: 从 _source 字段中提取并返回的字段列表
        :arg parent: 父文档的 ID
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg realtime: 指定以实时模式还是搜索模式执行操作
        :arg refresh: 在执行操作前刷新包含文档的分片
        :arg routing: 特定路由值
        :arg stored_fields: 以逗号分隔的存储字段列表，将在响应中返回
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 "internal"、"external"、"external_gte"、"force"
        """
        for param in (index, doc_type, id):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('HEAD', _make_path(index,
                                                                 doc_type, id), params=params)

    @query_params('_source', '_source_exclude', '_source_include', 'parent',
                  'preference', 'realtime', 'refresh', 'routing', 'version',
                  'version_type')
    def exists_source(self, index, doc_type, id, params=None):
        """
        `<http://www.elastic.co/guide/en/elasticsearch/reference/master/docs-get.html>`_

        :arg index: 索引名称
        :arg doc_type: 文件类型；使用 `_all`获取所有类型中第一个与 ID 匹配的文件
        :arg id: 文档 ID
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include:  从 _source 字段中提取并返回的字段列表
        :arg parent: 父文档的 ID
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg realtime: 指定以实时模式还是搜索模式执行操作
        :arg refresh: 在执行操作前刷新包含文档的分片
        :arg routing: 特定路由值
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 "internal"、"external"、"external_gte"、"force"
        """
        for param in (index, doc_type, id):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('HEAD', _make_path(index,
                                                                 doc_type, id, '_source'), params=params)

    @query_params('_source', '_source_exclude', '_source_include', 'parent',
                  'preference', 'realtime', 'refresh', 'routing', 'stored_fields',
                  'version', 'version_type')
    def get(self, index, doc_type, id, params=None):
        """
        c根据 id 从索引中获取类型化的 JSON 文档。
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html>`_

        :arg index: 索引名称
        :arg doc_type: 文件类型（使用 `_all`获取所有类型中第一个与 ID 匹配的文件）
        :arg id: 文档 ID
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include:  从 _source 字段中提取并返回的字段列表
        :arg parent: 父文档的 ID
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg realtime: 指定以实时模式还是搜索模式执行操作
        :arg refresh: 在执行操作前刷新包含文档的分片
        :arg routing: 特定路由值
        :arg stored_fields: 以逗号分隔的存储字段列表，将在响应中返回
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 "internal"、"external"、"external_gte"、"force"
        """
        for param in (index, doc_type, id):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, id), params=params)

    @query_params('_source', '_source_exclude', '_source_include', 'parent',
                  'preference', 'realtime', 'refresh', 'routing', 'version',
                  'version_type')
    def get_source(self, index, doc_type, id, params=None):
        """
        通过索引、类型和 ID 获取文档的来源。
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-get.html>`_

        :arg index: 索引名称
        :arg doc_type: 文件类型；使用 `_all`获取所有类型中第一个与 ID 匹配的文件
        :arg id: 文档 ID
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include:  从 _source 字段中提取并返回的字段列表
        :arg parent: 父文档的 ID
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg realtime: 指定以实时模式还是搜索模式执行操作
        :arg refresh: 在执行操作前刷新包含文档的分片
        :arg routing: 特定路由值
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 "internal"、"external"、"external_gte"、"force"
        """
        for param in (index, doc_type, id):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, id, '_source'), params=params)

    @query_params('_source', '_source_exclude', '_source_include', 'preference',
                  'realtime', 'refresh', 'routing', 'stored_fields')
    def mget(self, body, index=None, doc_type=None, params=None):
        """
        根据索引、类型（可选）和 ID 获取多个文档。
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-multi-get.html>`_

        :arg body: 文档标识符；可以是`docs`（包含完整的文档信息）或`ids`（当在 URL 中提供索引和类型时）。
        :arg index: 索引名称
        :arg doc_type: The type of the document
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include:  从 _source 字段中提取并返回的字段列表
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg realtime: 指定以实时模式还是搜索模式执行操作
        :arg refresh: 在执行操作前刷新包含文档的分片
        :arg routing: 特定路由值
        :arg stored_fields: 以逗号分隔的存储字段列表，将在响应中返回
        """
        if body in SKIP_IN_PATH:
            raise ValueError("Empty value passed for a required argument 'body'.")
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, '_mget'), params=params, body=body)

    @query_params('_source', '_source_exclude', '_source_include', 'fields',
                  'lang', 'parent', 'refresh', 'retry_on_conflict', 'routing', 'timeout',
                  'timestamp', 'ttl', 'version', 'version_type', 'wait_for_active_shards')
    def update(self, index, doc_type, id, body=None, params=None):
        """
        根据脚本或提供的部分数据更新文档。
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update.html>`_

        :arg index: 索引名称
        :arg doc_type: The type of the document
        :arg id: 文档ID
        :arg body: 使用 "脚本 "或部分 "文档 "的请求定义
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include:  从 _source 字段中提取并返回的字段列表
        :arg fields: 以逗号分隔的字段列表，包含要在响应中返回的字段
        :arg lang: 脚本语言（默认：无痛）
        :arg parent: 父文档的 ID。该 ID 仅用于路由选择，以及在向上插入请求时使用。
        :arg refresh: 如果 `true`，则刷新受影响的碎片，使该操作在搜索中可见；如果 `wait_for` ，则等待刷新，使该操作在搜索中可见；如果 `false`（默认），则不刷新： true"、"false"、"wait_for
        :arg retry_on_conflict: 指定发生冲突时重试操作的次数（默认值：0）
        :arg routing: 特定路由值
        :arg timeout: 显式操作超时
        :arg timestamp: 文件的明确时间戳
        :arg ttl: 文件失效时间
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 内部"、"强制
        :arg wait_for_active_shards: 设置更新操作前必须激活的分区副本数量。默认设置为 1，表示仅主分区处于活动状态。对于所有分区副本，设置为 "all"，否则设置为任何小于或等于分区副本总数（副本数 + 1）的非负值。
        """
        for param in (index, doc_type, id):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('POST', _make_path(index,
                                                                 doc_type, id, '_update'), params=params, body=body)

    @query_params('_source', '_source_exclude', '_source_include',
                  'allow_no_indices', 'analyze_wildcard', 'analyzer',
                  'batched_reduce_size', 'default_operator', 'df', 'docvalue_fields',
                  'expand_wildcards', 'explain', 'from_', 'ignore_unavailable', 'lenient',
                  'max_concurrent_shard_requests', 'pre_filter_shard_size', 'preference',
                  'q', 'request_cache', 'routing', 'scroll', 'search_type', 'size',
                  'sort', 'stats', 'stored_fields', 'suggest_field', 'suggest_mode',
                  'suggest_size', 'suggest_text', 'terminate_after', 'timeout',
                  'track_scores', 'track_total_hits', 'typed_keys', 'version')
    def search(self, index=None, doc_type=None, body=None, params=None):
        """
        执行搜索查询，并返回与查询匹配的搜索结果。
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html>`_

        :arg index: 以逗号分隔的要搜索的索引名称列表；使用 `_all` 或空字符串可对所有索引执行操作
        :arg doc_type: 用逗号分隔的要搜索的文件类型列表；留空表示对所有类型执行操作
        :arg body: 使用查询 DSL 的搜索定义
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include:  从 _source 字段中提取并返回的字段列表
        :arg allow_no_indices: 如果通配符索引表达式解析为无具体索引，是否忽略。(这包括 `_all`字符串或未指定索引时）
        :arg analyze_wildcard: 指定是否要分析通配符和前缀查询（默认值：false）
        :arg analyzer: 查询字符串使用的分析器
        :arg batched_reduce_size: 应在协调节点上一次性减少的分片结果数量。如果请求中可能存在大量分片，则应将此值用作一种保护机制，以减少每个搜索请求的内存开销。
        :arg default_operator: 查询字符串查询的默认运算符（AND 或 OR），默认为'OR'，有效选项为 与"、"或
        :arg df: 在查询字符串中没有给出字段前缀的情况下作为默认字段使用的字段
        :arg docvalue_fields: 以逗号分隔的字段列表，用于返回每个命中字段的 docvalue 表示值
        :arg expand_wildcards: 是否将通配符表达式扩展为开放、封闭或两者兼有的具体索引，默认为 "开放"，有效选项为："开放"、"封闭"、"无"、"全部"： 打开"、"关闭"、"无"、"全部., default 'open', valid choices are: 'open', 'closed', 'none', 'all'
        :arg explain: 指定是否将分数计算的详细信息作为命中的一部分返回
        :arg from\_: Starting offset (default: 0)
        :arg ignore_unavailable: 指定的具体索引在不可用（丢失或关闭）时是否应被忽略
        :arg lenient: 指定是否应忽略基于格式的查询失败（例如向数字字段提供文本）。
        :arg max_concurrent_shard_requests: 此搜索同时执行的并发分区请求数。该值应用于限制搜索对集群的影响，以限制并发分片请求的数量，默认为'默认值随集群中节点数量的增加而增加，但最多不超过 256 个'。
        :arg pre_filter_shard_size: 一个阈值，当搜索请求扩展到的分区数量超过该阈值时，该阈值会强制执行预过滤往返，根据查询重写对搜索分区进行预过滤。如果某个分区无法根据其重写方法匹配任何文档，例如，如果日期过滤器必须匹配，但分区边界和查询是不相交的，那么这种过滤器迂回就会大大限制分区的数量，默认值为 128。
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg q: 用 Lucene 查询字符串语法进行查询
        :arg request_cache: 指定是否对该请求使用请求缓存，默认为索引级别设置
        :arg routing: 以逗号分隔的特定路由值列表
        :arg scroll: 指定滚动搜索时索引视图保持一致的时间
        :arg search_type: 搜索操作类型，有效选项为 query_then_fetch"、"dfs_query_then_fetch
        :arg size: 返回的点击数（默认值：10）
        :arg sort: 以逗号分隔的 <字段>:<方向> 对列表
        :arg stats: 为记录和统计目的对请求进行特定 "标记
        :arg stored_fields: 以逗号分隔的存储字段列表，作为命中的一部分返回
        :arg suggest_field: 指定建议使用的字段
        :arg suggest_mode: 指定建议模式，默认为 "missing"，有效选项为  'missing', 'popular', 'always'
        :arg suggest_size: 回复多少建议
        :arg suggest_text: 应返回建议的源文本
        :arg terminate_after: 每个分区要收集的文档的最大数量，当达到该数量时，查询执行将提前终止。
        :arg timeout: 显式操作超时
        :arg track_scores: 是否计算并返回分数，即使分数不用于排序
        :arg track_total_hits: 指明是否要跟踪与查询匹配的文件数量
        :arg typed_keys: 指定聚合和建议器名称是否应在响应中以各自的类型作为前缀
        :arg version: 指定是否将文档版本作为命中的一部分返回
        """
        # from is a reserved word so it cannot be used, use from_ instead
        if 'from_' in params:
            params['from'] = params.pop('from_')

        if doc_type and not index:
            index = '_all'
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, '_search'), params=params, body=body)

    @query_params('_source', '_source_exclude', '_source_include',
                  'allow_no_indices', 'analyze_wildcard', 'analyzer', 'conflicts',
                  'default_operator', 'df', 'expand_wildcards', 'from_',
                  'ignore_unavailable', 'lenient', 'pipeline', 'preference', 'q',
                  'refresh', 'request_cache', 'requests_per_second', 'routing', 'scroll',
                  'scroll_size', 'search_timeout', 'search_type', 'size', 'slices',
                  'sort', 'stats', 'terminate_after', 'timeout', 'version',
                  'version_type', 'wait_for_active_shards', 'wait_for_completion')
    def update_by_query(self, index, doc_type=None, body=None, params=None):
        """
        对与查询匹配的所有文档进行更新。
        `<https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update-by-query.html>`_

        :arg index: 以逗号分隔的要搜索的索引名称列表；使用 `_all` 或空字符串可对所有索引执行操作
        :arg doc_type: 用逗号分隔的要搜索的文件类型列表；留空表示对所有类型执行操作
        :arg body: 使用查询 DSL 的搜索定义
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include:  从 _source 字段中提取并返回的字段列表
        :arg allow_no_indices: 如果通配符索引表达式解析为无具体索引，是否忽略。(这包括 `_all`字符串或未指定索引时）
        :arg analyze_wildcard: 指定是否要分析通配符和前缀查询（默认值：false）
        :arg analyzer: 查询字符串使用的分析器
        :arg conflicts: What to do when the update by query hits version conflicts?, default 'abort', valid choices are: 'abort', 'proceed'
        :arg default_operator: 查询字符串查询的默认运算符（AND 或 OR），默认为'OR'，有效选项为 与"、"或
        :arg df: 在查询字符串中没有给出字段前缀的情况下作为默认字段使用的字段
        :arg expand_wildcards: 是否将通配符表达式扩展为开放、封闭或两者兼有的具体索引，默认为 "开放"，有效选项为："开放"、"封闭"、"无"、"全部"： 打开"、"关闭"、"无"、"全部., default 'open', valid choices are: 'open', 'closed', 'none', 'all'
        :arg from\_: Starting offset (default: 0)
        :arg ignore_unavailable: 指定的具体索引在不可用（丢失或关闭）时是否应被忽略
        :arg lenient: 指定是否应忽略基于格式的查询失败（例如向数字字段提供文本）。
        :arg pipeline: Ingest pipeline to set on index requests made by this action. (default: none)
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg q: 用 Lucene 查询字符串语法进行查询
        :arg refresh: Should the effected indexes be refreshed?
        :arg request_cache: 指定是否对该请求使用请求缓存，默认为索引级别设置
        :arg requests_per_second: The throttle to set on this request in sub-requests per second. -1 means no throttle., default 0
        :arg routing: 以逗号分隔的特定路由值列表
        :arg scroll: 指定滚动搜索时索引视图保持一致的时间
        :arg scroll_size: 通过查询更新的滚动请求的大小
        :arg search_timeout: 每次搜索请求的明确超时。默认为无超时。
        :arg search_type: 搜索操作类型，有效选项为 query_then_fetch"、"dfs_query_then_fetch
        :arg size: 返回的点击数（默认值：10）
        :arg slices: 该任务应划分的子任务数。默认为 1，表示任务不被分割成子任务。
        :arg sort: 以逗号分隔的 <字段>:<方向> 对列表
        :arg stats: 为记录和统计目的对请求进行特定 "标记
        :arg terminate_after: 每个分区要收集的文档的最大数量，当达到该数量时，查询执行将提前终止。
        :arg timeout: 每个批量请求等待不可用分区的时间，默认为 "1m"。
        :arg version: 指定是否将文档版本作为命中的一部分返回
        :arg version_type: Should the document increment the version number (internal) on hit or not (reindex)文件是否应在命中时增加版本号（内部）（重新索引）
        :arg wait_for_active_shards: 设置通过查询进行更新操作前必须激活的分区副本数量。默认设置为 1，表示仅主分区处于活动状态。对于所有分区副本，设置为 "all"，否则设置为任何小于或等于分区副本总数（副本数 + 1）的非负值。
        :arg wait_for_completion: 请求是否应阻塞，直到查询更新操作完成，默认为 True
        """
        if index in SKIP_IN_PATH:
            raise ValueError("Empty value passed for a required argument 'index'.")
        return self.transport.perform_request('POST', _make_path(index,
                                                                 doc_type, '_update_by_query'), params=params,
                                              body=body)

    @query_params('refresh', 'requests_per_second', 'slices', 'timeout',
                  'wait_for_active_shards', 'wait_for_completion')
    def reindex(self, body, params=None):
        """
        将所有文件从一个索引重新索引到另一个索引。
        `<https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html>`_

        :arg body: 使用查询 DSL 的搜索定义 and the prototype for the index request.
        :arg refresh: Should the effected indexes be refreshed?
        :arg requests_per_second: The throttle to set on this request in sub-requests per second. -1 means no throttle., default 0
        :arg slices: 该任务应划分的子任务数。默认为 1，表示任务不被分割成子任务。
        :arg timeout: 每个批量请求等待不可用分区的时间，默认为 "1m"。
        :arg wait_for_active_shards: Sets the number of shard copies that must be active before proceeding with the reindex operation. Defaults to 1, meaning the primary shard only. Set to `all` for all shard copies, otherwise set to any non-negative value less than or equal to the total number of copies for the shard (number of replicas + 1)
        :arg wait_for_completion: Should the request should block until the reindex is complete., default True
        """
        if body in SKIP_IN_PATH:
            raise ValueError("Empty value passed for a required argument 'body'.")
        return self.transport.perform_request('POST', '/_reindex',
                                              params=params, body=body)

    @query_params('requests_per_second')
    def reindex_rethrottle(self, task_id=None, params=None):
        """
        Change the value of ``requests_per_second`` of a running ``reindex`` task.
        `<https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html>`_

        :arg task_id: The task id to rethrottle
        :arg requests_per_second: The throttle to set on this request in
            floating sub-requests per second. -1 means set no throttle.
        """
        return self.transport.perform_request('POST', _make_path('_reindex',
                                                                 task_id, '_rethrottle'), params=params)

    @query_params('_source', '_source_exclude', '_source_include',
                  'allow_no_indices', 'analyze_wildcard', 'analyzer', 'conflicts',
                  'default_operator', 'df', 'expand_wildcards', 'from_',
                  'ignore_unavailable', 'lenient', 'preference', 'q', 'refresh',
                  'request_cache', 'requests_per_second', 'routing', 'scroll',
                  'scroll_size', 'search_timeout', 'search_type', 'size', 'slices',
                  'sort', 'stats', 'terminate_after', 'timeout', 'version',
                  'wait_for_active_shards', 'wait_for_completion')
    def delete_by_query(self, index, body, doc_type=None, params=None):
        """
        删除所有与查询匹配的文件。
        `<https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-delete-by-query.html>`_

        :arg index: 以逗号分隔的要搜索的索引名称列表；使用 `_all` 或空字符串可对所有索引执行操作
        :arg body: 使用查询 DSL 的搜索定义
        :arg doc_type: 用逗号分隔的要搜索的文件类型列表；留空表示对所有类型执行操作
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include:  从 _source 字段中提取并返回的字段列表
        :arg allow_no_indices: 如果通配符索引表达式解析为无具体索引，是否忽略。(这包括 `_all`字符串或未指定索引时）
        :arg analyze_wildcard: 指定是否要分析通配符和前缀查询（默认值：false）
        :arg analyzer: 查询字符串使用的分析器
        :arg conflicts: What to do when the delete-by-query hits version
            conflicts?, default 'abort', valid choices are: 'abort', 'proceed'
        :arg default_operator: 查询字符串查询的默认运算符（AND 或 OR），默认为'OR'，有效选项为 与"、"或
        :arg df: 在查询字符串中没有给出字段前缀的情况下作为默认字段使用的字段
        :arg expand_wildcards: 是否将通配符表达式扩展为开放、封闭或两者兼有的具体索引，默认为 "开放"，有效选项为："开放"、"封闭"、"无"、"全部"： 打开"、"关闭"、"无"、"全部., default 'open', valid choices are: 'open', 'closed', 'none', 'all'
        :arg from\_: Starting offset (default: 0)
        :arg ignore_unavailable: 指定的具体索引在不可用（丢失或关闭）时是否应被忽略
        :arg lenient: 指定是否应忽略基于格式的查询失败（例如向数字字段提供文本）。
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg q: 用 Lucene 查询字符串语法进行查询
        :arg refresh: Should the effected indexes be refreshed?
        :arg request_cache: 指定是否对该请求使用请求缓存，默认为索引级别设置
        :arg requests_per_second: The throttle for this request in sub-requests
            per second. -1 means no throttle., default 0
        :arg routing: 以逗号分隔的特定路由值列表
        :arg scroll: 指定滚动搜索时索引视图保持一致的时间
        :arg scroll_size: 通过查询更新的滚动请求的大小
        :arg search_timeout: 每次搜索请求的明确超时。默认为无超时。
        :arg search_type: 搜索操作类型，有效选项为 query_then_fetch"、"dfs_query_then_fetch
        :arg size: 返回的点击数（默认值：10）
        :arg slices: 该任务应划分的子任务数。默认为 1，表示任务不被分割成子任务。
        :arg sort: 以逗号分隔的 <字段>:<方向> 对列表
        :arg stats: 为记录和统计目的对请求进行特定 "标记
        :arg terminate_after: 每个分区要收集的文档的最大数量，当达到该数量时，查询执行将提前终止。
        :arg timeout: 每个批量请求等待不可用分区的时间，默认为 "1m"。
        :arg version: 指定是否将文档版本作为命中的一部分返回
        :arg wait_for_active_shards: Sets the number of shard copies that must be active before proceeding with the delete by query operation. Defaults to 1, meaning the primary shard only. Set to `all` for all shard copies, otherwise set to any non-negative value less than or equal to the total number of copies for the shard (number of replicas + 1)
        :arg wait_for_completion: Should the request should block until the delete-by-query is complete., default True
        """
        for param in (index, body):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('POST', _make_path(index,
                                                                 doc_type, '_delete_by_query'), params=params,
                                              body=body)

    @query_params('allow_no_indices', 'expand_wildcards', 'ignore_unavailable',
                  'local', 'preference', 'routing')
    def search_shards(self, index=None, doc_type=None, params=None):
        """
        The search shards api returns the indices and shards that a search request would be executed against. This can give useful feedback for working out issues or planning optimizations with routing and shard preferences.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-shards.html>`_

        :arg index: 以逗号分隔的要搜索的索引名称列表；使用 `_all` 或空字符串可对所有索引执行操作
        :arg allow_no_indices: 如果通配符索引表达式解析为无具体索引，是否忽略。(这包括 `_all`字符串或未指定索引时）
        :arg expand_wildcards: 是否将通配符表达式扩展为开放、封闭或两者兼有的具体索引，默认为 "开放"，有效选项为："开放"、"封闭"、"无"、"全部"： 打开"、"关闭"、"无"、"全部., default 'open', valid choices are: 'open', 'closed', 'none', 'all'
        :arg ignore_unavailable: 指定的具体索引在不可用（丢失或关闭）时是否应被忽略
        :arg local: Return local information, do not retrieve the state from master node (default: false)
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg routing: 特定路由值
        """
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, '_search_shards'), params=params)

    @query_params('allow_no_indices', 'expand_wildcards', 'explain',
                  'ignore_unavailable', 'preference', 'profile', 'routing', 'scroll',
                  'search_type', 'typed_keys')
    def search_template(self, index=None, doc_type=None, body=None, params=None):
        """
        A query that accepts a query template and a map of key/value pairs to fill in template parameters.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-template.html>`_

        :arg index: 以逗号分隔的要搜索的索引名称列表；使用 `_all` 或空字符串可对所有索引执行操作
        :arg doc_type: 用逗号分隔的要搜索的文件类型列表；留空表示对所有类型执行操作
        :arg body: The search definition template and its params
        :arg allow_no_indices: 如果通配符索引表达式解析为无具体索引，是否忽略。(这包括 `_all`字符串或未指定索引时）
        :arg expand_wildcards: 是否将通配符表达式扩展为开放、封闭或两者兼有的具体索引，默认为 "开放"，有效选项为："开放"、"封闭"、"无"、"全部"： 打开"、"关闭"、"无"、"全部., default 'open', valid choices are: 'open', 'closed', 'none', 'all'
        :arg explain: 指定是否将分数计算的详细信息作为命中的一部分返回
        :arg ignore_unavailable: 指定的具体索引在不可用（丢失或关闭）时是否应被忽略
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg profile: Specify whether to profile the query execution
        :arg routing: 以逗号分隔的特定路由值列表
        :arg scroll: 指定滚动搜索时索引视图保持一致的时间
        :arg search_type: Search operation type, valid choices are: 'query_then_fetch', 'query_and_fetch', 'dfs_query_then_fetch', 'dfs_query_and_fetch'
        :arg typed_keys: 指定聚合和建议器名称是否应在响应中以各自的类型作为前缀
        """
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, '_search', 'template'), params=params,
                                              body=body)

    @query_params('_source', '_source_exclude', '_source_include',
                  'analyze_wildcard', 'analyzer', 'default_operator', 'df', 'lenient',
                  'parent', 'preference', 'q', 'routing', 'stored_fields')
    def explain(self, index, doc_type, id, body=None, params=None):
        """
        The explain api computes a score explanation for a query and a specific document. This can give useful feedback whether a document matches or didn't match a specific query.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-explain.html>`_

        :arg index: 索引名称
        :arg doc_type: The type of the document
        :arg id: 文档 ID
        :arg body: The query definition using the Query DSL
        :arg _source: 返回 _source 字段或不返回 _source 字段的真或假，或者返回一个字段列表
        :arg _source_exclude: 从返回的 _source 字段中排除的字段列表
        :arg _source_include:  从 _source 字段中提取并返回的字段列表
        :arg analyze_wildcard: Specify whether wildcards and prefix queries in the query string query should be analyzed (default: false)
        :arg analyzer: The analyzer for the query string query
        :arg default_operator: 查询字符串查询的默认运算符（AND 或 OR），默认为'OR'，有效选项为 与"、"或
        :arg df: The default field for query string query (default: _all)
        :arg lenient: 指定是否应忽略基于格式的查询失败（例如向数字字段提供文本）。
        :arg parent: 父文档的 ID
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg q: 用 Lucene 查询字符串语法进行查询
        :arg routing: 特定路由值
        :arg stored_fields: 以逗号分隔的存储字段列表，将在响应中返回
        """
        for param in (index, doc_type, id):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, id, '_explain'), params=params, body=body)

    @query_params('scroll')
    def scroll(self, scroll_id=None, body=None, params=None):
        """
        Scroll a search request created by specifying the scroll parameter.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html>`_

        :arg scroll_id: The scroll ID
        :arg body: The scroll ID if not passed by URL or query parameter.
        :arg scroll: 指定滚动搜索时索引视图保持一致的时间
        """
        if scroll_id in SKIP_IN_PATH and body in SKIP_IN_PATH:
            raise ValueError("You need to supply scroll_id or body.")
        elif scroll_id and not body:
            body = {'scroll_id': scroll_id}
        elif scroll_id:
            params['scroll_id'] = scroll_id

        return self.transport.perform_request('GET', '/_search/scroll',
                                              params=params, body=body)

    @query_params()
    def clear_scroll(self, scroll_id=None, body=None, params=None):
        """
        Clear the scroll request created by specifying the scroll parameter to search.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html>`_

        :arg scroll_id: A comma-separated list of scroll IDs to clear
        :arg body: A comma-separated list of scroll IDs to clear if none was specified via the scroll_id parameter
        """
        if scroll_id in SKIP_IN_PATH and body in SKIP_IN_PATH:
            raise ValueError("You need to supply scroll_id or body.")
        elif scroll_id and not body:
            body = {'scroll_id': [scroll_id]}
        elif scroll_id:
            params['scroll_id'] = scroll_id

        return self.transport.perform_request('DELETE', '/_search/scroll',
                                              params=params, body=body)

    @query_params('parent', 'refresh', 'routing', 'timeout', 'version',
                  'version_type', 'wait_for_active_shards')
    def delete(self, index, doc_type, id, params=None):
        """
        Delete a typed JSON document from a specific index based on its id.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-delete.html>`_

        :arg index: 索引名称
        :arg doc_type: The type of the document
        :arg id: 文档 ID
        :arg parent: ID of parent document
        :arg refresh: 如果 `true`，则刷新受影响的碎片，使该操作在搜索中可见；如果 `wait_for` ，则等待刷新，使该操作在搜索中可见；如果 `false`（默认），则不刷新： true"、"false"、"wait_for
        :arg routing: 特定路由值
        :arg timeout: 显式操作超时
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 "internal"、"external"、"external_gte"、"force"
        :arg wait_for_active_shards: Sets the number of shard copies that must be active before proceeding with the delete operation. Defaults to 1, meaning the primary shard only. Set to `all` for all shard copies, otherwise set to any non-negative value less than or equal to the total number of copies for the shard (number of replicas + 1)
        """
        for param in (index, doc_type, id):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('DELETE', _make_path(index,
                                                                   doc_type, id), params=params)

    @query_params('allow_no_indices', 'analyze_wildcard', 'analyzer',
                  'default_operator', 'df', 'expand_wildcards', 'ignore_unavailable',
                  'lenient', 'min_score', 'preference', 'q', 'routing')
    def count(self, index=None, doc_type=None, body=None, params=None):
        """
        Execute a query and get the number of matches for that query.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-count.html>`_

        :arg index: A comma-separated list of indices to restrict the results
        :arg doc_type: A comma-separated list of types to restrict the results
        :arg body: A query to restrict the results specified with the Query DSL (optional)
        :arg allow_no_indices: 如果通配符索引表达式解析为无具体索引，是否忽略。(这包括 `_all`字符串或未指定索引时）
        :arg analyze_wildcard: 指定是否要分析通配符和前缀查询（默认值：false）
        :arg analyzer: 查询字符串使用的分析器
        :arg default_operator: 查询字符串查询的默认运算符（AND 或 OR），默认为'OR'，有效选项为 与"、"或
        :arg df: 在查询字符串中没有给出字段前缀的情况下作为默认字段使用的字段
        :arg expand_wildcards: 是否将通配符表达式扩展为开放、封闭或两者兼有的具体索引，默认为 "开放"，有效选项为："开放"、"封闭"、"无"、"全部"： 打开"、"关闭"、"无"、"全部., default 'open', valid choices are: 'open', 'closed', 'none', 'all'
        :arg ignore_unavailable: 指定的具体索引在不可用（丢失或关闭）时是否应被忽略
        :arg lenient: 指定是否应忽略基于格式的查询失败（例如向数字字段提供文本）。
        :arg min_score: Include only documents with a specific `_score` value in the result
        :arg preference: 指定执行操作的节点或分片（默认：随机）
        :arg q: 用 Lucene 查询字符串语法进行查询
        :arg routing: 特定路由值
        """
        if doc_type and not index:
            index = '_all'

        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, '_count'), params=params, body=body)

    @query_params('_source', '_source_exclude', '_source_include', 'fields',
                  'pipeline', 'refresh', 'routing', 'timeout', 'wait_for_active_shards')
    def bulk(self, body, index=None, doc_type=None, params=None):
        """
        执行批量操作
        See the :func:`~elasticsearch.helpers.bulk` helper function for a more
        friendly API.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html>`_

        :arg body: The operation definition and data (action-data pairs), separated by newlines
        :arg index: Default index for items which don't provide one
        :arg doc_type: Default document type for items which don't provide one
        :arg _source: True or false to return the _source field or not, or default list of fields to return, can be overridden on each sub-request
        :arg _source_exclude: Default list of fields to exclude from the returned _source field, can be overridden on each sub-request
        :arg _source_include: Default list of fields to extract and return from the _source field, can be overridden on each sub-request
        :arg fields: Default comma-separated list of fields to return in the response for updates, can be overridden on each sub-request
        :arg pipeline: The pipeline id to preprocess incoming documents with
        :arg refresh: 如果 `true`，则刷新受影响的碎片，使该操作在搜索中可见；如果 `wait_for` ，则等待刷新，使该操作在搜索中可见；如果 `false`（默认），则不刷新： true"、"false"、"wait_for
        :arg routing: 特定路由值
        :arg timeout: 显式操作超时
        :arg wait_for_active_shards: Sets the number of shard copies that must be active before proceeding with the bulk operation. Defaults to 1, meaning the primary shard only. Set to `all` for all shard copies, otherwise set to any non-negative value less than or equal to the total number of copies for the shard (number of replicas + 1)
        """
        if body in SKIP_IN_PATH:
            raise ValueError("Empty value passed for a required argument 'body'.")
        return self.transport.perform_request('POST', _make_path(index,
                                                                 doc_type, '_bulk'), params=params,
                                              body=self._bulk_body(body),
                                              headers={'content-type': 'application/x-ndjson'})

    @query_params('max_concurrent_searches', 'pre_filter_shard_size',
                  'search_type', 'typed_keys')
    def msearch(self, body, index=None, doc_type=None, params=None):
        """
        Execute several search requests within the same API.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-multi-search.html>`_

        :arg body: The request definitions (metadata-search request definition pairs), separated by newlines
        :arg index: A comma-separated list of index names to use as default
        :arg doc_type: A comma-separated list of document types to use as default
        :arg max_concurrent_searches: Controls the maximum number of concurrent searches the multi search api will execute
        :arg pre_filter_shard_size: 一个阈值，当搜索请求扩展到的分区数量超过该阈值时，该阈值会强制执行预过滤往返，根据查询重写对搜索分区进行预过滤。如果某个分区无法根据其重写方法匹配任何文档，例如，如果日期过滤器必须匹配，但分区边界和查询是不相交的，那么这种过滤器迂回就会大大限制分区的数量，默认值为 128。
        :arg search_type: Search operation type, valid choices are: 'query_then_fetch', 'query_and_fetch', 'dfs_query_then_fetch', 'dfs_query_and_fetch'
        :arg typed_keys: 指定聚合和建议器名称是否应在响应中以各自的类型作为前缀
        """
        if body in SKIP_IN_PATH:
            raise ValueError("Empty value passed for a required argument 'body'.")
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, '_msearch'), params=params,
                                              body=self._bulk_body(body),
                                              headers={'content-type': 'application/x-ndjson'})

    @query_params('field_statistics', 'fields', 'offsets', 'parent', 'payloads',
                  'positions', 'preference', 'realtime', 'routing', 'term_statistics',
                  'version', 'version_type')
    def termvectors(self, index, doc_type, id=None, body=None, params=None):
        """
        Returns information and statistics on terms in the fields of a particular document. The document could be stored in the index or artificially provided by the user (Added in 1.4). Note that for documents stored in the index, this is a near realtime API as the term vectors are not available until the next refresh.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-termvectors.html>`_

        :arg index: The index in which the document resides.
        :arg doc_type: The type of the document.
        :arg id: The id of the document, when not specified a doc param should be supplied.
        :arg body: Define parameters and or supply a document to get termvectors for. See documentation.
        :arg field_statistics: Specifies if document count, sum of document frequencies and sum of total term frequencies should be returned., default True
        :arg fields: A comma-separated list of fields to return.
        :arg offsets: Specifies if term offsets should be returned., default True
        :arg parent: Parent id of documents.
        :arg payloads: Specifies if term payloads should be returned., default True
        :arg positions: Specifies if term positions should be returned., default True
        :arg preference: 指定执行操作的节点或分片（默认：随机）.
        :arg realtime: Specifies if request is real-time as opposed to near-real-time (default: true).
        :arg routing: 特定路由值.
        :arg term_statistics: Specifies if total term frequency and document frequency should be returned., default False
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 "internal"、"external"、"external_gte"、"force"
        """
        for param in (index, doc_type):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, id, '_termvectors'), params=params, body=body)

    @query_params('field_statistics', 'fields', 'ids', 'offsets', 'parent',
                  'payloads', 'positions', 'preference', 'realtime', 'routing',
                  'term_statistics', 'version', 'version_type')
    def mtermvectors(self, index=None, doc_type=None, body=None, params=None):
        """
        Multi termvectors API allows to get multiple termvectors based on an
        index, type and id.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/docs-multi-termvectors.html>`_

        :arg index: The index in which the document resides.
        :arg doc_type: The type of the document.
        :arg body: Define ids, documents, parameters or a list of parameters per document here. You must at least provide a list of document ids. See documentation.
        :arg field_statistics: Specifies if document count, sum of document frequencies and sum of total term frequencies should be returned. Applies to all returned documents unless otherwise specified in body "params" or "docs"., default True
        :arg fields: A comma-separated list of fields to return. Applies to all returned documents unless otherwise specified in body "params" or "docs".
        :arg ids: A comma-separated list of documents ids. You must define ids as parameter or set "ids" or "docs" in the request body
        :arg offsets: Specifies if term offsets should be returned. Applies to all returned documents unless otherwise specified in body "params" or "docs"., default True
        :arg parent: Parent id of documents. Applies to all returned documents unless otherwise specified in body "params" or "docs".
        :arg payloads: Specifies if term payloads should be returned. Applies to all returned documents unless otherwise specified in body "params" or "docs"., default True
        :arg positions: Specifies if term positions should be returned. Applies to all returned documents unless otherwise specified in body "params" or "docs"., default True
        :arg preference: 指定执行操作的节点或分片（默认：随机） .Applies to all returned documents unless otherwise specified in body "params" or "docs".
        :arg realtime: Specifies if requests are real-time as opposed to near-real-time (default: true).
        :arg routing: 特定路由值. Applies to all returned documents unless otherwise specified in body "params" or "docs".
        :arg term_statistics: Specifies if total term frequency and document frequency should be returned. Applies to all returned documents unless otherwise specified in body "params" or "docs"., default False
        :arg version: 用于并发控制的明确版本号
        :arg version_type: 特定版本类型，有效选项包括 "internal"、"external"、"external_gte"、"force"
        """
        return self.transport.perform_request('GET', _make_path(index,
                                                                doc_type, '_mtermvectors'), params=params, body=body)

    @query_params()
    def put_script(self, id, body, context=None, params=None):
        """
        Create a script in given language with specified ID.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting.html>`_

        :arg id: Script ID
        :arg body: The document
        """
        for param in (id, body):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('PUT', _make_path('_scripts', id,
                                                                context), params=params, body=body)

    @query_params()
    def get_script(self, id, params=None):
        """
        Retrieve a script from the API.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/master/modules-scripting.html>`_

        :arg id: Script ID
        """
        if id in SKIP_IN_PATH:
            raise ValueError("Empty value passed for a required argument 'id'.")
        return self.transport.perform_request('GET', _make_path('_scripts', id),
                                              params=params)

    @query_params()
    def put_template(self, id, body, params=None):
        """
        Create a search template.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-template.html>`_

        :arg id: Template ID
        :arg body: The document
        """
        for param in (id, body):
            if param in SKIP_IN_PATH:
                raise ValueError("Empty value passed for a required argument.")
        return self.transport.perform_request('PUT', _make_path('_search',
                                                                'template', id), params=params, body=body)

    @query_params()
    def get_template(self, id, params=None):
        """
        Retrieve a search template.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-template.html>`_

        :arg id: Template ID
        """
        if id in SKIP_IN_PATH:
            raise ValueError("Empty value passed for a required argument 'id'.")
        return self.transport.perform_request('GET', _make_path('_search',
                                                                'template', id), params=params)

    @query_params()
    def delete_script(self, id, params=None):
        """
        Remove a stored script from elasticsearch.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/master/modules-scripting.html>`_

        :arg id: Script ID
        """
        if id in SKIP_IN_PATH:
            raise ValueError("Empty value passed for a required argument 'id'.")
        return self.transport.perform_request('DELETE', _make_path('_scripts',
                                                                   id), params=params)

    @query_params()
    def render_search_template(self, id=None, body=None, params=None):
        """
        `<http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/search-template.html>`_

        :arg id: The id of the stored search template
        :arg body: The search definition template and its params
        """
        return self.transport.perform_request('GET', _make_path('_render',
                                                                'template', id), params=params, body=body)

    @query_params('max_concurrent_searches', 'search_type', 'typed_keys')
    def msearch_template(self, body, index=None, doc_type=None, params=None):
        """
        The /_search/template endpoint allows to use the mustache language to
        pre render search requests, before they are executed and fill existing
        templates with template parameters.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-template.html>`_

        :arg body: The request definitions (metadata-search request definition pairs), separated by newlines
        :arg index: A comma-separated list of index names to use as default
        :arg doc_type: A comma-separated list of document types to use as default
        :arg max_concurrent_searches: Controls the maximum number of concurrent searches the multi search api will execute
        :arg search_type: Search operation type, valid choices are: 'query_then_fetch', 'query_and_fetch', 'dfs_query_then_fetch', 'dfs_query_and_fetch'
        :arg typed_keys: 指定聚合和建议器名称是否应在响应中以各自的类型作为前缀
        """
        if body in SKIP_IN_PATH:
            raise ValueError("Empty value passed for a required argument 'body'.")
        return self.transport.perform_request('GET', _make_path(index, doc_type,
                                                                '_msearch', 'template'), params=params,
                                              body=self._bulk_body(body),
                                              headers={'content-type': 'application/x-ndjson'})

    @query_params('allow_no_indices', 'expand_wildcards', 'fields',
                  'ignore_unavailable')
    def field_caps(self, index=None, body=None, params=None):
        """
        The field capabilities API allows to retrieve the capabilities of fields among multiple indices.
        `<http://www.elastic.co/guide/en/elasticsearch/reference/current/search-field-caps.html>`_

        :arg index: 以逗号分隔的索引名称列表；使用 `_all` 或空字符串可对所有索引执行操作
        :arg body: Field json objects containing an array of field names
        :arg allow_no_indices: 如果通配符索引表达式解析为无具体索引，是否忽略。(这包括 `_all`字符串或未指定索引时）
        :arg expand_wildcards: 是否将通配符表达式扩展为开放、封闭或两者兼有的具体索引，默认为 "开放"，有效选项为："开放"、"封闭"、"无"、"全部"： 打开"、"关闭"、"无"、"全部., default 'open', valid choices are: 'open', 'closed', 'none', 'all'
        :arg fields: A comma-separated list of field names
        :arg ignore_unavailable: 指定的具体索引在不可用（丢失或关闭）时是否应被忽略
        """
        return self.transport.perform_request('GET', _make_path(index,
                                                                '_field_caps'), params=params, body=body)
