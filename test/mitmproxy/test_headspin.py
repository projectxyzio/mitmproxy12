from mitmproxy import headspin
from mitmproxy.connection import Client
from mitmproxy.options import Options
from mitmproxy.proxy.context import Context


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
