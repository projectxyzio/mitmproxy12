import pytest

from mitmproxy import headspin
from mitmproxy.addons.next_layer import NextLayer
from mitmproxy.connection import Client
from mitmproxy.connection import Server
from mitmproxy.options import Options
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers import TCPLayer
from mitmproxy.proxy.layers import modes
from mitmproxy.proxy.layers import tls as tls_layer
from mitmproxy.proxy import server_hooks
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


@pytest.mark.parametrize(
    "server_address,server_sni,client_sni,prefer_sni,expected",
    [
        (("93.184.216.34", 443), None, None, False, ("93.184.216.34", 443)),
        (("93.184.216.34", 443), "example.com", None, False, ("93.184.216.34", 443)),
        (("93.184.216.34", 443), None, "example.com", True, ("example.com", 443)),
        (None, "server.example", None, False, ("server.example", 443)),
        (None, None, "client.example", False, ("client.example", 443)),
        (None, None, None, False, None),
    ],
)
def test_tls_named_address_resolution(
    server_address, server_sni, client_sni, prefer_sni, expected
):
    opts = Options()
    client = Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=0,
        sni=client_sni,
    )
    server = Server(address=server_address, sni=server_sni)
    ctx = Context(client, opts)
    ctx.server = server

    assert tls_layer.tls_named_address(ctx, prefer_sni=prefer_sni) == expected


def test_fire_tlsexception_updates_ignore_hosts():
    from mitmproxy.addons.proxyserver import Proxyserver
    from test.mitmproxy.proxy import tutils

    opts = Options()
    Proxyserver().load(opts)
    client = Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=0,
    )
    ctx = Context(client, opts)

    event_ph = tutils.Placeholder(headspin.TlsExceptionEvent)
    gen = tls_layer.fire_tlsexception(ctx, ("tls.example.com", 443))
    hook = next(gen)
    assert isinstance(hook, server_hooks.TlsExceptionHook)
    event_ph.setdefault(hook.event)
    assert event_ph().named_address == ("tls.example.com", 443)
    with pytest.raises(StopIteration):
        next(gen)
    assert "tls[.]example[.]com:443" in ctx.options.ignore_hosts


def test_fire_tlsexception_respects_addon_keep_in_session():
    """Simulate proxy server: addons run on the hook before apply_host_policy."""
    from mitmproxy.addons.proxyserver import Proxyserver

    opts = Options()
    Proxyserver().load(opts)
    client = Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=0,
    )
    ctx = Context(client, opts)

    gen = tls_layer.fire_tlsexception(ctx, ("keep-tls.example", 443))
    hook = next(gen)

    def capture_like_tlsexception(event: headspin.TlsExceptionEvent) -> None:
        event.keep_in_session = True

    capture_like_tlsexception(hook.event)

    with pytest.raises(StopIteration):
        next(gen)
    assert ctx.options.ignore_hosts == []


def test_fire_protocolexception_respects_addon_keep_in_session():
    """Simulate capture addon setting keep_in_session before host policy runs."""
    from mitmproxy.addons.proxyserver import Proxyserver

    opts = Options()
    Proxyserver().load(opts)
    client = Client(
        peername=("127.0.0.1", 12345),
        sockname=("127.0.0.1", 8080),
        timestamp_start=0,
    )
    ctx = Context(client, opts)
    exc = OSError("connection refused")

    gen = server_hooks.fire_protocolexception(ctx, ("keep-proto.example", 443), exc)
    hook = next(gen)

    def capture_like_protocolexception(
        event: headspin.ProtocolExceptionEvent,
    ) -> None:
        event.keep_in_session = True

    capture_like_protocolexception(hook.event)

    with pytest.raises(StopIteration):
        next(gen)
    assert ctx.options.ignore_hosts == []


def test_headspin_hooks_dispatch_to_addons():
    """Addons receive tlsexception/protocolexception with the HeadSpin event payload."""

    class CaptureLikeAddon:
        def __init__(self):
            self.tls_events: list[headspin.TlsExceptionEvent] = []
            self.protocol_events: list[headspin.ProtocolExceptionEvent] = []

        def tlsexception(self, event: headspin.TlsExceptionEvent) -> None:
            self.tls_events.append(event)

        def protocolexception(self, event: headspin.ProtocolExceptionEvent) -> None:
            event.keep_in_session = True
            self.protocol_events.append(event)

    addon = CaptureLikeAddon()
    with taddons.context(addon, loadcore=False) as tctx:
        tls_event = headspin.TlsExceptionEvent(("tls.addon.example", 443))
        tctx.master.addons.trigger(server_hooks.TlsExceptionHook(tls_event))
        assert len(addon.tls_events) == 1
        assert addon.tls_events[0].named_address == ("tls.addon.example", 443)

        proto_exc = RuntimeError("connect failed")
        proto_event = headspin.ProtocolExceptionEvent(
            ("proto.addon.example", 443), proto_exc
        )
        tctx.master.addons.trigger(server_hooks.ProtocolExceptionHook(proto_event))
        assert len(addon.protocol_events) == 1
        assert addon.protocol_events[0].server_address == ("proto.addon.example", 443)
        assert addon.protocol_events[0].e is proto_exc
        assert addon.protocol_events[0].keep_in_session is True


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
