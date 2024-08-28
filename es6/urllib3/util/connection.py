from __future__ import absolute_import

import socket

from ..contrib import _appengine_environ
from ..exceptions import LocationParseError
from ..packages import six
from .wait import NoWayToWaitForSocketError, wait_for_read


def is_connection_dropped(conn):
    sock = getattr(conn, "sock", False)
    if sock is False:
        return False
    if sock is None:
        return True
    try:
        return wait_for_read(sock, timeout=0.0)
    except NoWayToWaitForSocketError:  # Platform-specific: AppEngine
        return False


def create_connection(
        address,
        timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address=None,
        socket_options=None,
):
    host, port = address
    if host.startswith("["):
        host = host.strip("[]")
    err = None

    family = allowed_gai_family()

    try:
        host.encode("idna")
    except UnicodeError:
        return six.raise_from(
            LocationParseError(u"'%s', label empty or too long" % host), None
        )

    for res in socket.getaddrinfo(host, port, family, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)

            # If provided, set socket level options before connecting.
            _set_socket_options(sock, socket_options)

            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock

        except socket.error as e:
            err = e
            if sock is not None:
                sock.close()
                sock = None

    if err is not None:
        raise err

    raise socket.error("getaddrinfo returns an empty list")


def _set_socket_options(sock, options):
    if options is None:
        return

    for opt in options:
        sock.setsockopt(*opt)


def allowed_gai_family():
    family = socket.AF_INET
    if HAS_IPV6:
        family = socket.AF_UNSPEC
    return family


def _has_ipv6(host):
    sock = None
    has_ipv6 = False

    if _appengine_environ.is_appengine_sandbox():
        return False

    if socket.has_ipv6:
        try:
            sock = socket.socket(socket.AF_INET6)
            sock.bind((host, 0))
            has_ipv6 = True
        except Exception:
            pass

    if sock:
        sock.close()
    return has_ipv6


HAS_IPV6 = _has_ipv6("::1")
