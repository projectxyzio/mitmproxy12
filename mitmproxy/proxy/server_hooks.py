from dataclasses import dataclass

from . import commands
from mitmproxy import connection
from mitmproxy import headspin


@dataclass
class ClientConnectedHook(commands.StartHook):
    """
    A client has connected to mitmproxy. Note that a connection can
    correspond to multiple HTTP requests.

    Setting client.error kills the connection.
    """

    client: connection.Client


@dataclass
class ClientDisconnectedHook(commands.StartHook):
    """
    A client connection has been closed (either by us or the client).
    """

    client: connection.Client


@dataclass
class ServerConnectionHookData:
    """Event data for server connection event hooks."""

    server: connection.Server
    """The server connection this hook is about."""
    client: connection.Client
    """The client on the other end."""


@dataclass
class ServerConnectHook(commands.StartHook):
    """
    Mitmproxy is about to connect to a server.
    Note that a connection can correspond to multiple requests.

    Setting data.server.error kills the connection.
    """

    data: ServerConnectionHookData


@dataclass
class ServerConnectedHook(commands.StartHook):
    """
    Mitmproxy has connected to a server.
    """

    data: ServerConnectionHookData


@dataclass
class ServerDisconnectedHook(commands.StartHook):
    """
    A server connection has been closed (either by us or the server).
    """

    data: ServerConnectionHookData


@dataclass
class ServerConnectErrorHook(commands.StartHook):
    """
    Mitmproxy failed to connect to a server.

    Every server connection will receive either a server_connected or a server_connect_error event, but not both.
    """

    data: ServerConnectionHookData


@dataclass
class TlsExceptionHook(commands.StartHook):
    """
    HeadSpin: TLS handshake failed for a named host.

    Addons may set ``event.keep_in_session`` to keep the host in the capture session.
    Otherwise the host is added to ``ignore_hosts`` for TCP passthrough.
    """

    event: headspin.TlsExceptionEvent


TlsExceptionHook.name = "tlsexception"


@dataclass
class ProtocolExceptionHook(commands.StartHook):
    """
    HeadSpin: a protocol or connection error occurred for a server.

    Addons may set ``event.keep_in_session`` to keep the host in the capture session.
    """

    event: headspin.ProtocolExceptionEvent


ProtocolExceptionHook.name = "protocolexception"
