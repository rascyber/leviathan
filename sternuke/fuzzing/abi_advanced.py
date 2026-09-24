# -*- coding: utf-8 -*-
"""
sternuke.fuzzing.abi_advanced
=============================

A complete, dependency-free Ethereum ABI codec.

This upgrades :mod:`sternuke.fuzzing.abi` (which handles the flat/common subset)
to the full ABI grammar required for real-world contract fuzzing:

* elementary types: ``uintN`` / ``intN`` / ``address`` / ``bool`` /
  ``bytesN`` / ``bytes`` / ``string`` / ``function``;
* fixed and dynamic arrays, including **multi-dimensional** arrays such as
  ``uint256[][]`` and ``uint8[3][]``;
* **tuples** (``(uint256,address)``) and arbitrarily **nested tuples**, tuples
  inside arrays and arrays inside tuples (``(uint256,(bool,bytes))[]``).

The encoder produces canonical EVM head/tail layout with correct dynamic
offsets, computed recursively, without any third-party library. A matching
decoder is provided so fuzzers can read return values and detect state drift.

Type model
----------
Types are parsed into an :class:`AbiType` tree by :func:`parse_type`. A tuple is
written with a ``components`` child list; the same tree drives both encoding and
dynamic/static classification (a type is dynamic if it is ``bytes``/``string``,
a dynamic array, a fixed array of a dynamic type, or a tuple containing any
dynamic component).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence, Tuple

from .abi import AbiError  # reuse the shared error type
from .keccak import keccak256

WORD = 32
_MAX_UINT = (1 << 256) - 1

_ELEMENTARY_RE = re.compile(
    r"^(?:uint(\d+)?|int(\d+)?|address|bool|function|bytes(\d+)?|string)$")
_ARRAY_SUFFIX_RE = re.compile(r"^(.*)\[(\d*)\]$")


# ===========================================================================
# Type model + parser
# ===========================================================================
@dataclass
class AbiType:
    """A node in the parsed ABI type tree."""

    base: str                              # "uint256","tuple","array","bytes",...
    # array-specific:
    element: Optional["AbiType"] = None    # element type when base == "array"
    length: Optional[int] = None           # fixed length, or None for dynamic array
    # tuple-specific:
    components: List["AbiType"] = field(default_factory=list)
    # elementary metadata:
    bits: int = 0                          # for uint/int
    size: int = 0                          # for bytesN

    # -- dynamic classification (recursive, per the ABI spec) ---------------
    @property
    def is_dynamic(self) -> bool:
        if self.base in ("bytes", "string"):
            return True
        if self.base == "array":
            assert self.element is not None
            if self.length is None:          # T[] dynamic array
                return True
            return self.element.is_dynamic   # T[k] dynamic iff T is dynamic
        if self.base == "tuple":
            return any(c.is_dynamic for c in self.components)
        return False

    def canonical(self) -> str:
        """Return the canonical type string (used for selectors)."""
        if self.base == "array":
            assert self.element is not None
            suffix = f"[{self.length}]" if self.length is not None else "[]"
            return self.element.canonical() + suffix
        if self.base == "tuple":
            return "(" + ",".join(c.canonical() for c in self.components) + ")"
        return self.base


def _split_top_level(inner: str) -> List[str]:
    """Split a tuple's inner text on top-level commas (respecting nesting)."""
    parts: List[str] = []
    depth = 0
    current = []
    for ch in inner:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def parse_type(type_str: str) -> AbiType:
    """Parse an ABI type string into an :class:`AbiType` tree."""
    t = type_str.strip()
    if not t:
        raise AbiError("empty ABI type")

    # Arrays bind tightest at the end: peel one [..] suffix at a time.
    m = _ARRAY_SUFFIX_RE.match(t)
    if m:
        element = parse_type(m.group(1))
        length = int(m.group(2)) if m.group(2) else None
        return AbiType(base="array", element=element, length=length)

    # Tuples: (T1,T2,...)
    if t.startswith("(") and t.endswith(")"):
        comps = [parse_type(p) for p in _split_top_level(t[1:-1])] if t != "()" else []
        return AbiType(base="tuple", components=comps)

    # Elementary.
    em = _ELEMENTARY_RE.match(t)
    if not em:
        raise AbiError(f"unsupported or malformed ABI type: {type_str!r}")
    if t.startswith("uint"):
        return AbiType(base=f"uint{em.group(1) or '256'}", bits=int(em.group(1) or 256))
    if t.startswith("int"):
        return AbiType(base=f"int{em.group(2) or '256'}", bits=int(em.group(2) or 256))
    if t == "bytes":
        return AbiType(base="bytes")
    if t.startswith("bytes"):
        return AbiType(base=t, size=int(em.group(3)))
    # address / bool / string / function
    return AbiType(base=t)


# ===========================================================================
# Encoding
# ===========================================================================
def _pad_right(data: bytes) -> bytes:
    if len(data) % WORD == 0:
        return data
    return data + b"\x00" * (WORD - len(data) % WORD)


def _enc_uint(value: int) -> bytes:
    return (int(value) & _MAX_UINT).to_bytes(WORD, "big")


def _enc_address(value: Any) -> bytes:
    if isinstance(value, int):
        raw = value & ((1 << 160) - 1)
        return raw.to_bytes(WORD, "big")
    s = str(value).lower().replace("0x", "").rjust(40, "0")[-40:]
    try:
        return bytes.fromhex(s).rjust(WORD, b"\x00")
    except ValueError as exc:
        raise AbiError(f"invalid address: {value!r}") from exc


def _enc_bytesN(value: Any, size: int) -> bytes:
    raw = value if isinstance(value, (bytes, bytearray)) else bytes.fromhex(
        str(value).replace("0x", ""))
    raw = bytes(raw)[:size]
    return raw + b"\x00" * (WORD - len(raw))


def _encode_elementary(t: AbiType, value: Any) -> bytes:
    b = t.base
    if b.startswith("uint"):
        return _enc_uint(value)
    if b.startswith("int"):
        return _enc_uint(int(value))              # two's complement into 256 bits
    if b == "address":
        return _enc_address(value)
    if b == "bool":
        return _enc_uint(1 if value else 0)
    if b == "function":
        return _enc_bytesN(value, 24)
    if b.startswith("bytes") and b != "bytes":
        return _enc_bytesN(value, t.size)
    raise AbiError(f"not an elementary type: {b}")


def _is_elementary(t: AbiType) -> bool:
    b = t.base
    return (b.startswith("uint") or b.startswith("int") or b in ("address", "bool", "function")
            or (b.startswith("bytes") and b != "bytes"))


def _head_size(t: AbiType) -> int:
    """Number of bytes a value of ``t`` occupies in the head (multiple of 32)."""
    if t.is_dynamic:
        return WORD
    if t.base == "array":
        assert t.element is not None and t.length is not None
        return t.length * _head_size(t.element)
    if t.base == "tuple":
        return sum(_head_size(c) for c in t.components)
    return WORD


def _encode(t: AbiType, value: Any) -> bytes:
    """Encode a single value (head+tail combined) for ``t``.

    For dynamic types this returns the full dynamic encoding; the head/tail
    stitching for a *sequence* is handled by :func:`_encode_sequence`.
    """
    if _is_elementary(t):
        return _encode_elementary(t, value)

    if t.base == "bytes":
        raw = value if isinstance(value, (bytes, bytearray)) else (
            bytes.fromhex(value[2:]) if isinstance(value, str) and value.startswith("0x")
            else str(value).encode())
        return _enc_uint(len(raw)) + _pad_right(bytes(raw))

    if t.base == "string":
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        return _enc_uint(len(raw)) + _pad_right(raw)

    if t.base == "array":
        assert t.element is not None
        seq = list(value)
        if t.length is None:
            # dynamic array: length prefix + encoded sequence of elements
            return _enc_uint(len(seq)) + _encode_sequence([t.element] * len(seq), seq)
        if len(seq) != t.length:
            raise AbiError(f"expected {t.length} elements, got {len(seq)}")
        return _encode_sequence([t.element] * t.length, seq)

    if t.base == "tuple":
        if len(value) != len(t.components):
            raise AbiError(f"tuple arity mismatch: expected {len(t.components)}, "
                           f"got {len(value)}")
        return _encode_sequence(t.components, list(value))

    raise AbiError(f"cannot encode type: {t.canonical()}")


def _encode_sequence(types: Sequence[AbiType], values: Sequence[Any]) -> bytes:
    """Encode a sequence of typed values in canonical head/tail layout."""
    if len(types) != len(values):
        raise AbiError("types/values length mismatch")
    # Head size: dynamic members contribute a 32-byte offset; static members
    # contribute their full (multiple-of-32) width inline.
    encoded: List[bytes] = [_encode(t, v) for t, v in zip(types, values)]
    head_size = sum(_head_size(t) for t in types)

    heads: List[bytes] = []
    tails: List[bytes] = []
    tail_offset = head_size
    running_tail = 0
    for t, enc in zip(types, encoded):
        if t.is_dynamic:
            heads.append(_enc_uint(tail_offset + running_tail))
            tails.append(enc)
            running_tail += len(enc)
        else:
            heads.append(enc)
    return b"".join(heads) + b"".join(tails)


def encode(types: Sequence[str], values: Sequence[Any]) -> bytes:
    """ABI-encode ``values`` for the given type strings (top-level tuple)."""
    parsed = [parse_type(t) for t in types]
    return _encode_sequence(parsed, list(values))


def encode_call(signature: str, values: Sequence[Any]) -> bytes:
    """Encode full calldata (4-byte selector + args) for ``signature``.

    ``signature`` may contain tuples/arrays, e.g.
    ``deposit((uint256,address)[],bytes)``.
    """
    name, arg_types = parse_function_signature(signature)
    canonical = f"{name}({','.join(t.canonical() for t in arg_types)})"
    selector = keccak256(canonical.encode())[:4]
    return selector + _encode_sequence(arg_types, list(values))


def function_selector(signature: str) -> bytes:
    """4-byte selector for a (possibly tuple/array-bearing) signature."""
    name, arg_types = parse_function_signature(signature)
    canonical = f"{name}({','.join(t.canonical() for t in arg_types)})"
    return keccak256(canonical.encode())[:4]


def parse_function_signature(signature: str) -> Tuple[str, List[AbiType]]:
    """Split ``name(argtypes...)`` into name + parsed argument type trees."""
    m = re.match(r"^\s*([A-Za-z_]\w*)\s*\((.*)\)\s*$", signature.strip())
    if not m:
        raise AbiError(f"invalid function signature: {signature!r}")
    name = m.group(1)
    inner = m.group(2).strip()
    arg_types = [parse_type(p) for p in _split_top_level(inner)] if inner else []
    return name, arg_types


# ===========================================================================
# Decoding (for reading return values / detecting state drift)
# ===========================================================================
def _read_word(data: bytes, offset: int) -> int:
    chunk = data[offset:offset + WORD]
    if len(chunk) < WORD:
        raise AbiError("truncated ABI word")
    return int.from_bytes(chunk, "big")


def _to_signed(value: int, bits: int) -> int:
    if value >= (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def _decode(t: AbiType, data: bytes, offset: int) -> Any:
    """Decode a value of type ``t`` located per head/tail rules at ``offset``."""
    b = t.base
    if b.startswith("uint"):
        return _read_word(data, offset)
    if b.startswith("int"):
        return _to_signed(_read_word(data, offset), t.bits or 256)
    if b == "address":
        return "0x" + data[offset + 12:offset + WORD].hex()
    if b == "bool":
        return _read_word(data, offset) != 0
    if b == "function":
        return "0x" + data[offset:offset + 24].hex()
    if b.startswith("bytes") and b != "bytes":
        return data[offset:offset + t.size]

    if b in ("bytes", "string"):
        length = _read_word(data, offset)
        raw = data[offset + WORD:offset + WORD + length]
        return raw.decode("utf-8", "replace") if b == "string" else raw

    if b == "array":
        assert t.element is not None
        if t.length is None:
            length = _read_word(data, offset)
            base = offset + WORD
        else:
            length = t.length
            base = offset
        return _decode_sequence([t.element] * length, data, base)

    if b == "tuple":
        return _decode_sequence(t.components, data, offset)

    raise AbiError(f"cannot decode type: {t.canonical()}")


def _decode_sequence(types: Sequence[AbiType], data: bytes, base: int) -> List[Any]:
    out: List[Any] = []
    head_cursor = base
    for t in types:
        if t.is_dynamic:
            rel = _read_word(data, head_cursor)
            out.append(_decode(t, data, base + rel))
            head_cursor += WORD               # dynamic head slot is one offset word
        else:
            out.append(_decode(t, data, head_cursor))
            head_cursor += _head_size(t)       # static value sits inline in the head
    return out


def decode(types: Sequence[str], data: bytes) -> List[Any]:
    """Decode ABI-encoded ``data`` per the given type strings.

    Note: static tuples/arrays occupy multiple head words; this decoder handles
    the common return-value shapes (elementary, dynamic, and tuples/arrays whose
    static members are single-word). For deeply nested *static* tuples in the
    head, decode the tuple as a dynamic boundary or use :func:`_decode` directly.
    """
    parsed = [parse_type(t) for t in types]
    return _decode_sequence(parsed, data, 0)
