# -*- coding: utf-8 -*-
"""
sternuke.fuzzing.guards
=======================

Scope guards for the fuzzing subsystem.

Fuzzing generates high volumes of malformed input, so sternuke restricts where
those inputs may be delivered. By default every fuzzer refuses anything that is
not clearly local / operator-controlled:

* smart-contract fuzzing must target a loopback / private-range JSON-RPC node;
* binary fuzzing must target a regular local executable file;
* web fuzzing reuses the engine's :class:`ScanPolicy` (throttles + optional
  host allow-list) and additionally refuses non-local hosts unless the operator
  passes ``allow_remote=True`` to explicitly accept responsibility.

These guards are about keeping the tool an *assessment* instrument on systems
you are authorised to test - not a mechanism for reaching third parties.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


class ScopeError(RuntimeError):
    """Raised when a fuzzing target falls outside the permitted local scope."""


_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _resolve_is_local(host: str) -> bool:
    if host in _LOCAL_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Resolve a hostname; treat any resolved private/loopback address as local.
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False
        return all(_ip_is_local(info[4][0]) for info in infos) and bool(infos)
    return _ip_is_local(str(ip))


def _ip_is_local(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def assert_local_rpc(url: str, *, allow_remote: bool = False) -> str:
    """Validate a JSON-RPC endpoint is loopback/private. Returns the URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"unsupported RPC scheme: {parsed.scheme!r}")
    host = parsed.hostname or ""
    if allow_remote:
        return url
    if not _resolve_is_local(host):
        raise ScopeError(
            f"contract fuzzing target {host!r} is not local. Point --rpc at a "
            f"local test node (e.g. http://127.0.0.1:8545) or pass allow_remote "
            f"to accept responsibility for authorisation.")
    return url


def assert_local_executable(path: str) -> str:
    """Validate a binary-fuzz target is an existing local file. Returns the path."""
    if not os.path.isfile(path):
        raise ScopeError(f"binary target is not a file: {path!r}")
    if not os.access(path, os.X_OK):
        raise ScopeError(f"binary target is not executable: {path!r}")
    return os.path.abspath(path)


def assert_web_scope(url: str, *, allow_remote: bool = False) -> str:
    """Validate a web-fuzz target host, unless remote is explicitly accepted."""
    host = urlparse(url).hostname or ""
    if allow_remote or _resolve_is_local(host):
        return url
    raise ScopeError(
        f"web fuzzing target {host!r} is not local. Pass allow_remote=True to "
        f"fuzz a target you are explicitly authorised to test.")
