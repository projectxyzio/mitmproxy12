"""
HeadSpin-specific mitmproxy extensions re-ported from mitmproxy5.

Used by network capture addons for smart ignore (tlsexception / protocolexception)
and session host filtering.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.proxy.context import Context

logger = logging.getLogger(__name__)


@dataclass
class TlsExceptionEvent:
    named_address: tuple[str, int]
    keep_in_session: bool = False


# deprecated alias kept for compatibility with mitm5 capture addons
TlsException = TlsExceptionEvent


@dataclass
class ProtocolExceptionEvent:
    server_address: tuple[str, int]
    e: BaseException
    keep_in_session: bool = False


def _host_pattern(named_address: tuple[str, int]) -> str:
    host, port = named_address
    host = host.replace(".", "[.]")
    return f"{host}:{port}"


def exclude_host_from_session(context: Context, named_address: tuple[str, int]) -> None:
    pattern = _host_pattern(named_address)
    logger.info("Ignoring %s from the session.", pattern)
    opts = context.options
    if opts.allow_hosts:
        # allow-list mode: only listed hosts are intercepted.
        return
    ignore_hosts = list(opts.ignore_hosts)
    if pattern in ignore_hosts:
        return
    ignore_hosts.append(pattern)
    opts.update(ignore_hosts=ignore_hosts)


def keep_host_in_session(context: Context, named_address: tuple[str, int]) -> None:
    pattern = f"{named_address[0]}:{named_address[1]}"
    logger.info("Keeping %s in the session.", pattern)


def apply_host_policy(
    context: Context, named_address: tuple[str, int], keep_in_session: bool
) -> None:
    if keep_in_session:
        keep_host_in_session(context, named_address)
    else:
        exclude_host_from_session(context, named_address)
