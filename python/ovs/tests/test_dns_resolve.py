import contextlib
import ipaddress
import sys
import time
from unittest import mock

import pytest

from ovs import dns_resolve
from ovs import socket_util


HOSTS = [("192.0.2.1", "fake.ip4.domain", "192.0.2.1"),
         ("2001:db8:2::1", "fake.ip6.domain", "2001:db8:2::1"),
         ("192.0.2.2", "fake.both.domain", "192.0.2.2"),
         ("2001:db8:2::2", "fake.both.domain", "192.0.2.2")]


def _tmp_file(path, content):
    path.write_text(content)
    assert content == path.read_text()
    return path


@pytest.fixture(params=[False, True], ids=["not_daemon", "daemon"])
def resolver_factory(monkeypatch, tmp_path, request):
    # Allow delaying the instantiation of the DNSResolver
    def resolver_factory(hosts=HOSTS):
        path = tmp_path / "hosts"
        content = "\n".join(f"{ip}\t{host}" for ip, host, _ in hosts)
        _tmp_file(path, content)

        with monkeypatch.context() as m:
            m.setenv("OVS_HOSTS_FILE", str(path))
            # Test with both is_daemon False and True
            resolver = dns_resolve.DNSResolver(request.param)
            assert resolver._is_daemon == request.param
            return dns_resolve.DNSResolver(request.param)

    yield resolver_factory
    dns_resolve.DNSResolver._instance = None


@contextlib.contextmanager
def DNSResolver(*args, **kwargs):
    """Clean up after returning a dns_resolver.DNSResolver

    Since it is a singleton, and pytest runs all tests in the same process,
    we can't use dns_resolver.DNSResolver directly in these tests. This
    context manager will reset the singleton at the end of the with block.
    """
    resolver = dns_resolve.DNSResolver(*args, **kwargs)
    try:
        yield resolver
    finally:
        dns_resolve.DNSResolver._instance = None


@pytest.fixture
def unbound_conf(tmp_path):
    path = tmp_path / "unbound.conf"
    content = """
    server:
        verbosity: 1
    """
    return _tmp_file(path, content)


@pytest.fixture
def resolv_conf(tmp_path):
    path = tmp_path / "resolv.conf"
    content = "nameserver 127.0.0.1"
    return _tmp_file(path, content)


@pytest.fixture
def hosts_file(tmp_path):
    path = tmp_path / "hosts"
    content = "127.0.0.1\tfakelocalhost.localdomain"
    return _tmp_file(path, content)


@pytest.fixture
def missing_file(tmp_path):
    f = tmp_path / "missing_file"
    assert not f.exists()
    return f


@pytest.fixture(params=[False, True], ids=["with unbound", "without unbound"])
def missing_unbound(monkeypatch, request):
    if request.param:
        monkeypatch.setitem(sys.modules, 'unbound', None)
        monkeypatch.delitem(dns_resolve.__dict__, "unbound")
    return request.param


def test_missing_unbound(missing_unbound, resolver_factory):
    resolver = resolver_factory()  # Dont fail even w/o unbound
    assert resolver.dns_enabled == (not missing_unbound)


def test_DNSRequest_defaults():
    req = dns_resolve.DNSRequest(HOSTS[0][1])
    assert HOSTS[0][1] == req.name
    assert req.state == req.INVALID
    assert req.time == req.result == req.ttl is None
    assert str(req)


def test_DNSResolver_singleton():
    with DNSResolver(True) as r1:
        assert r1._is_daemon
        r2 = dns_resolve.DNSResolver(False)
        assert r1 == r2
        assert r1._is_daemon


def _resolve(resolver, host, fn=dns_resolve.resolve):
    """Handle sync/async lookups, giving up if more than 1 second has passed"""

    timeout = 1
    start = time.time()
    name = fn(host)
    if resolver._is_daemon:
        while name is None:
            name = fn(host)
            if name:
                break
            time.sleep(0.01)
            end = time.time()
            if end - start > timeout:
                break
    if name:
        return name
    raise LookupError(f"{host} not found")


@pytest.mark.parametrize("ip,host,expected", HOSTS)
def test_resolve_addresses(missing_unbound, resolver_factory, ip, host,
                           expected):
    resolver = resolver_factory()
    if missing_unbound:
        with pytest.raises(LookupError):
            _resolve(resolver, host)
    else:
        result = _resolve(resolver, host)
        assert ipaddress.ip_address(expected) == ipaddress.ip_address(result)


def test_resolve_unknown_host(missing_unbound, resolver_factory):
    resolver = resolver_factory()
    with pytest.raises(LookupError):
        _resolve(resolver, "fake.notadomain")


def test_resolve_process_error():
    with DNSResolver(True) as resolver:
        with mock.patch.object(resolver._ctx, "process", return_value=-1):
            assert resolver.resolve("fake.domain") is None


def test_resolve_resolve_error():
    with DNSResolver(False) as resolver:
        with mock.patch.object(resolver._ctx, "resolve",
                               return_value=(-1, None)):
            assert resolver.resolve("fake.domain") is None


def test_resolve_resolve_async_error():
    with DNSResolver(True) as resolver:
        with mock.patch.object(resolver._ctx, "resolve_async",
                               return_value=(-1, None)):
            with pytest.raises(LookupError):
                _resolve(resolver, "fake.domain")


@pytest.mark.parametrize("file,raises",
                         [(None, False),
                          ("missing_file", dns_resolve.UnboundException),
                          ("unbound_conf", False)])
def test_set_unbound_conf(monkeypatch, missing_unbound, resolver_factory,
                          request, file, raises):
    if file:
        file = str(request.getfixturevalue(file))
        monkeypatch.setenv("OVS_UNBOUND_CONF", file)
    resolver = resolver_factory()  # Doesn't raise
    if missing_unbound:
        assert resolver._set_unbound_conf() is None
        return
    with mock.patch.object(resolver._ctx, "config",
                           side_effect=resolver._ctx.config) as c:
        if raises:
            with pytest.raises(raises):
                resolver._set_unbound_conf()
        else:
            resolver._set_unbound_conf()
        if file:
            c.assert_called_once_with(file)
        else:
            c.assert_not_called()


@pytest.mark.parametrize("file,raises",
                         [(None, False),
                          ("missing_file", dns_resolve.UnboundException),
                          ("resolv_conf", False)])
def test_resolv_conf(monkeypatch, missing_unbound, resolver_factory, request,
                     file, raises):
    if file:
        file = str(request.getfixturevalue(file))
        monkeypatch.setenv("OVS_RESOLV_CONF", file)
    resolver = resolver_factory()  # Doesn't raise
    if missing_unbound:
        assert resolver._set_resolv_conf() is None
        return
    with mock.patch.object(resolver._ctx, "resolvconf",
                           side_effect=resolver._ctx.resolvconf) as c:
        if raises:
            with pytest.raises(raises):
                resolver._set_resolv_conf()
        else:
            resolver._set_resolv_conf()
        c.assert_called_once_with(file)


@pytest.mark.parametrize("file,raises",
                         [(None, False),
                          ("missing_file", dns_resolve.UnboundException),
                          ("hosts_file", False)])
def test_hosts(monkeypatch, missing_unbound, resolver_factory, request, file,
               raises):
    if file:
        file = str(request.getfixturevalue(file))
        monkeypatch.setenv("OVS_HOSTS_FILE", file)
    resolver = resolver_factory()  # Doesn't raise
    if missing_unbound:
        assert resolver._set_hosts_file() is None
        return
    with mock.patch.object(resolver._ctx, "hosts",
                           side_effect=resolver._ctx.hosts) as c:
        if raises:
            with pytest.raises(raises):
                resolver._set_hosts_file()
        else:
            resolver._set_hosts_file()
        c.assert_called_once_with(file)


def test_UnboundException(missing_unbound):
    with pytest.raises(dns_resolve.UnboundException):
        raise dns_resolve.UnboundException("Fake exception", -1)


@pytest.mark.parametrize("ip,host,expected", HOSTS)
def test_inet_parse_active(resolver_factory, ip, host, expected):
    resolver = resolver_factory()

    def fn(name):
        # Return the same thing _resolve() would so we can call
        # this multiple times for the is_daemon=True case
        return socket_util.inet_parse_active(f"{name}:6640", 6640,
                                             raises=False)[0] or None

    # parsing IPs still works
    IP = _resolve(resolver, ip, fn)
    assert ipaddress.ip_address(ip) == ipaddress.ip_address(IP)
    # parsing hosts works
    IP = _resolve(resolver, host, fn)
    assert ipaddress.ip_address(IP) == ipaddress.ip_address(expected)
