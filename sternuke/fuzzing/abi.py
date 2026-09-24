# -*- coding: utf-8 -*-
"""
sternuke.fuzzing.abi
====================

A minimal, dependency-free Ethereum ABI encoder sufficient for property-based
smart-contract fuzzing.

Supported types:

* ``uintN`` / ``intN`` (N a multiple of 8, 8..256)
* ``address``
* ``bool``
* ``bytesN`` (fixed, 1..32)
* ``bytes`` / ``string`` (dynamic)
* one level of ``T[]`` dynamic arrays of the above static types

This is intentionally a subset - enough to drive the vast majority of public
entry points and invariant checks - not a full ABI codec. Unsupported types
raise :class:`AbiError` so callers can skip a function rather than mis-encode it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Sequence, Tuple

from .keccak import keccak256

WORD = 32
_UINT_RE = re.compile(r"^uint(\d+)?$")
_INT_RE = re.compile(r"^int(\d+)?$")
_BYTES_N_RE = re.compile(r"^bytes(\d+)$")


class AbiError(ValueError):
    """Raised for ABI types the minimal encoder does not support."""


@dataclass
class AbiParam:
    """A single function parameter type descriptor."""

    raw: str

    @property
    def is_dynamic(self) -> bool:
        return self.raw in ("bytes", "string") or self.raw.endswith("[]")


def _pad32(data: bytes, left: bool = True) -> bytes:
    if len(data) > WORD:
        raise AbiError(f"value exceeds 32 bytes: {len(data)}")
    pad = b"\x00" * (WORD - len(data))
    return (pad + data) if left else (data + pad)


_MAX_UINT = (1 << 256) - 1


def _encode_uint(value: int, bits: int = 256) -> bytes:
    # Wrap into the 256-bit word (two's-complement for negatives).
    return (int(value) & _MAX_UINT).to_bytes(WORD, "big")


def _encode_int(value: int, bits: int = 256) -> bytes:
    # Two's-complement into 256 bits.
    return (int(value) & _MAX_UINT).to_bytes(WORD, "big")


def _encode_address(value: Any) -> bytes:
    if isinstance(value, int):
        raw = value.to_bytes(20, "big")
    else:
        s = str(value).lower().replace("0x", "")
        s = s.rjust(40, "0")[-40:]
        raw = bytes.fromhex(s)
    return _pad32(raw, left=True)


def _encode_static(param: str, value: Any) -> bytes:
    if _UINT_RE.match(param):
        bits = int(_UINT_RE.match(param).group(1) or 256)
        return _encode_uint(int(value), bits)
    if _INT_RE.match(param):
        bits = int(_INT_RE.match(param).group(1) or 256)
        return _encode_int(int(value), bits)
    if param == "address":
        return _encode_address(value)
    if param == "bool":
        return _encode_uint(1 if value else 0, 8)
    m = _BYTES_N_RE.match(param)
    if m:
        n = int(m.group(1))
        raw = value if isinstance(value, (bytes, bytearray)) else bytes.fromhex(
            str(value).replace("0x", ""))
        if len(raw) > n:
            raw = raw[:n]
        return _pad32(bytes(raw), left=False)
    raise AbiError(f"unsupported static type: {param}")


def _encode_dynamic(param: str, value: Any) -> bytes:
    if param in ("bytes", "string"):
        raw = value.encode() if isinstance(value, str) else bytes(value)
        head = _encode_uint(len(raw))
        body = raw + b"\x00" * ((WORD - len(raw) % WORD) % WORD)
        return head + body
    if param.endswith("[]"):
        base = param[:-2]
        seq: Sequence[Any] = value if isinstance(value, (list, tuple)) else [value]
        out = _encode_uint(len(seq))
        for item in seq:
            out += _encode_static(base, item)
        return out
    raise AbiError(f"unsupported dynamic type: {param}")


def encode_parameters(types: Sequence[str], values: Sequence[Any]) -> bytes:
    """ABI-encode ``values`` according to ``types`` (head/tail layout)."""
    if len(types) != len(values):
        raise AbiError("types/values length mismatch")
    params = [AbiParam(t) for t in types]
    head_parts: List[bytes] = []
    tail_parts: List[bytes] = []
    head_len = WORD * len(params)
    for p, v in zip(params, values):
        if p.is_dynamic:
            head_parts.append(_encode_uint(head_len + sum(len(t) for t in tail_parts)))
            tail_parts.append(_encode_dynamic(p.raw, v))
        else:
            head_parts.append(_encode_static(p.raw, v))
    return b"".join(head_parts) + b"".join(tail_parts)


def function_selector(signature: str) -> bytes:
    """4-byte selector for a canonical signature like ``transfer(address,uint256)``."""
    return keccak256(signature.encode())[:4]


def parse_signature(signature: str) -> Tuple[str, List[str]]:
    """Split ``name(t1,t2)`` into ``("name", ["t1", "t2"])``."""
    m = re.match(r"^\s*([A-Za-z_]\w*)\s*\((.*)\)\s*$", signature)
    if not m:
        raise AbiError(f"invalid function signature: {signature!r}")
    name = m.group(1)
    inner = m.group(2).strip()
    types = [t.strip() for t in inner.split(",")] if inner else []
    return name, types


def encode_call(signature: str, values: Sequence[Any]) -> bytes:
    """Encode a full calldata blob (selector + encoded args) for ``signature``."""
    name, types = parse_signature(signature)
    return function_selector(f"{name}({','.join(types)})") + encode_parameters(types, values)
