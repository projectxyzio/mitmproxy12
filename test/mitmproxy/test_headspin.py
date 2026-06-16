from mitmproxy import headspin
from mitmproxy.addons.next_layer import NextLayer
from mitmproxy.connection import Client
from mitmproxy.options import Options
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers import TCPLayer
from mitmproxy.proxy.layers import modes
from mitmproxy.test import taddons


def test_exclude_host_from_session():
    opts = Options()
    client = Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=0,
    )
    context = Context(client, opts)

    headspin.exclude_host_from_session(context, ("example.com", 443))
    assert "example[.]com:443" in context.options.ignore_hosts

    headspin.exclude_host_from_session(context, ("example.com", 443))
    assert context.options.ignore_hosts.count("example[.]com:443") == 1


def test_exclude_host_skipped_for_allow_hosts():
    opts = Options()
    opts.update(allow_hosts=["allowed.example:443"])
    client = Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=0,
    )
    context = Context(client, opts)

    headspin.exclude_host_from_session(context, ("blocked.example", 443))
    assert context.options.ignore_hosts == []


def test_apply_host_policy_keep():
    opts = Options()
    client = Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=0,
    )
    context = Context(client, opts)

    headspin.apply_host_policy(context, ("keep.example", 443), keep_in_session=True)
    assert context.options.ignore_hosts == []


def test_apply_host_policy_exclude():
    opts = Options()
    client = Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=0,
    )
    context = Context(client, opts)

    headspin.apply_host_policy(context, ("bad.example.com", 443), keep_in_session=False)
    assert "bad[.]example[.]com:443" in context.options.ignore_hosts

    headspin.apply_host_policy(context, ("bad.example.com", 443), keep_in_session=True)
    assert context.options.ignore_hosts.count("bad[.]example[.]com:443") == 1


def test_fire_protocolexception_updates_ignore_hosts():
    from mitmproxy.addons.proxyserver import Proxyserver
    from mitmproxy.proxy import server_hooks
    from test.mitmproxy.proxy import tutils

    opts = Options()
    Proxyserver().load(opts)
    client = Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=0,
    )
    ctx = Context(client, opts)

    event_ph = tutils.Placeholder(headspin.ProtocolExceptionEvent)
    exc = OSError("connection refused")

    cmds = list(
        server_hooks.fire_protocolexception(ctx, ("proto.example.com", 443), exc)
    )
    assert len(cmds) == 1
    assert isinstance(cmds[0], server_hooks.ProtocolExceptionHook)
    event_ph.setdefault(cmds[0].event)
    assert event_ph().server_address == ("proto.example.com", 443)
    assert event_ph().e is exc
    assert "proto[.]example[.]com:443" in ctx.options.ignore_hosts


def test_protocolexception_smart_ignore_enables_passthrough():
    """After protocolexception exclude, NextLayer should TCP-passthrough the host."""
    nl = NextLayer()
    with taddons.context(nl) as tctx:
        client = Client(
            peername=("127.0.0.1", 12345),
            sockname=("127.0.0.1", 8080),
            timestamp_start=0,
        )
        ctx = Context(client, tctx.options)
        ctx.layers.append(modes.TransparentProxy(ctx))
        ctx.server.address = ("unreachable.example.com", 443)

        headspin.exclude_host_from_session(ctx, ("unreachable.example.com", 443))
        assert nl._ignore_connection(ctx, b"", b"") is True

        layer = nl._next_layer(ctx, b"", b"")
        assert isinstance(layer, TCPLayer)
        assert layer.flow is None


def test_tls_exception_event_defaults():
    event = headspin.TlsExceptionEvent(("host", 443))
    assert event.named_address == ("host", 443)
    assert event.keep_in_session is False


def test_protocol_exception_event():
    exc = RuntimeError("test")
    event = headspin.ProtocolExceptionEvent(("host", 443), exc)
    assert event.server_address == ("host", 443)
    assert event.e is exc
    assert event.keep_in_session is False


def test_smart_ignore_enables_next_layer_passthrough():
    """After tlsexception exclude, NextLayer should TCP-passthrough the host."""
    nl = NextLayer()
    with taddons.context(nl) as tctx:
        client = Client(
            peername=("127.0.0.1", 12345),
            sockname=("127.0.0.1", 8080),
            timestamp_start=0,
            sni="example.com",
        )
        ctx = Context(client, tctx.options)
        ctx.layers.append(modes.TransparentProxy(ctx))
        ctx.server.address = ("93.184.216.34", 443)
        ctx.server.peername = ("93.184.216.34", 443)

        assert nl._ignore_connection(ctx, b"", b"") is False

        headspin.exclude_host_from_session(ctx, ("example.com", 443))
        assert nl._ignore_connection(ctx, b"", b"") is True

        layer = nl._next_layer(ctx, b"", b"")
        assert isinstance(layer, TCPLayer)
        assert layer.flow is None


def test_smart_ignore_matches_server_address_pattern():
    nl = NextLayer()
    with taddons.context(nl) as tctx:
        client = Client(
            peername=("127.0.0.1", 12345),
            sockname=("127.0.0.1", 8080),
            timestamp_start=0,
        )
        ctx = Context(client, tctx.options)
        ctx.server.address = ("bad.example.com", 443)
        ctx.server.peername = ("10.0.0.1", 443)

        headspin.exclude_host_from_session(ctx, ("bad.example.com", 443))
        assert nl._ignore_connection(ctx, b"", b"") is True
