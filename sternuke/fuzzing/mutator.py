# -*- coding: utf-8 -*-
"""
sternuke.fuzzing.mutator
========================

The automated payload-mutation core shared by every sternuke fuzzer.

It provides three layers that the domain fuzzers (web, contract, binary)
compose as needed:

* :class:`ByteMutator` - AFL-style byte/bit-level mutations over raw ``bytes``
  (flips, arithmetic, "interesting" value injection, block splice/insert/delete,
  and stacked "havoc"). Deterministic given a seed for reproducible campaigns.
* :class:`TypedMutator` - value-aware mutation of ABI-typed arguments
  (integers -> boundaries/overflow candidates, addresses -> edge accounts,
  bytes -> length games). Used by the smart-contract fuzzer.
* :class:`Corpus` and :class:`CrashBucket` - a growing input corpus and a
  crash de-duplicator shared by the binary fuzzer's triage stage.

The mutators only transform *inputs*; deciding what to do with a mutated input
(and against which authorised target) is the domain fuzzer's job.
"""

from __future__ import annotations

import hashlib
import os
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

# 8/16/32-bit "interesting" values that historically surface edge-case bugs.
_INTERESTING_8 = [0x00, 0x01, 0x7F, 0x80, 0xFF]
_INTERESTING_16 = [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF, 0x00FF, 0xFF00]
_INTERESTING_32 = [0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


class ByteMutator:
    """AFL-inspired byte-level mutation engine over ``bytes`` seeds."""

    def __init__(self, seed: int = 0, dictionary: Optional[Sequence[bytes]] = None):
        self.rng = random.Random(seed)
        self.dictionary: List[bytes] = list(dictionary or [])

    # -- individual strategies ----------------------------------------------
    def bit_flip(self, data: bytearray) -> bytearray:
        if not data:
            return data
        i = self.rng.randrange(len(data))
        bit = self.rng.randrange(8)
        data[i] ^= (1 << bit)
        return data

    def byte_flip(self, data: bytearray) -> bytearray:
        if not data:
            return data
        i = self.rng.randrange(len(data))
        data[i] ^= 0xFF
        return data

    def arithmetic(self, data: bytearray) -> bytearray:
        if not data:
            return data
        i = self.rng.randrange(len(data))
        delta = self.rng.randint(-35, 35)
        data[i] = (data[i] + delta) & 0xFF
        return data

    def interesting(self, data: bytearray) -> bytearray:
        if not data:
            return data
        i = self.rng.randrange(len(data))
        data[i] = self.rng.choice(_INTERESTING_8)
        if len(data) - i >= 2 and self.rng.random() < 0.5:
            val = self.rng.choice(_INTERESTING_16)
            data[i:i + 2] = val.to_bytes(2, self.rng.choice(["big", "little"]))
        elif len(data) - i >= 4 and self.rng.random() < 0.3:
            val = self.rng.choice(_INTERESTING_32)
            data[i:i + 4] = val.to_bytes(4, self.rng.choice(["big", "little"]))
        return data

    def insert_block(self, data: bytearray) -> bytearray:
        n = self.rng.randint(1, 8)
        block = bytes(self.rng.randrange(256) for _ in range(n))
        pos = self.rng.randrange(len(data) + 1)
        data[pos:pos] = block
        return data

    def delete_block(self, data: bytearray) -> bytearray:
        if len(data) <= 1:
            return data
        n = self.rng.randint(1, max(1, len(data) // 4))
        pos = self.rng.randrange(len(data) - n + 1)
        del data[pos:pos + n]
        return data

    def duplicate_block(self, data: bytearray) -> bytearray:
        if not data:
            return data
        n = self.rng.randint(1, max(1, len(data) // 4))
        pos = self.rng.randrange(len(data) - n + 1) if len(data) > n else 0
        block = data[pos:pos + n]
        ins = self.rng.randrange(len(data) + 1)
        data[ins:ins] = block
        return data

    def dictionary_insert(self, data: bytearray) -> bytearray:
        if not self.dictionary:
            return self.interesting(data)
        token = self.rng.choice(self.dictionary)
        pos = self.rng.randrange(len(data) + 1)
        data[pos:pos] = token
        return data

    # -- composed mutation ---------------------------------------------------
    def _strategies(self) -> List[Callable[[bytearray], bytearray]]:
        base = [self.bit_flip, self.byte_flip, self.arithmetic, self.interesting,
                self.insert_block, self.delete_block, self.duplicate_block]
        if self.dictionary:
            base.append(self.dictionary_insert)
        return base

    def mutate(self, data: bytes, *, max_stack: int = 5) -> bytes:
        """Apply 1..max_stack stacked random mutations ("havoc")."""
        buf = bytearray(data)
        for _ in range(self.rng.randint(1, max_stack)):
            strat = self.rng.choice(self._strategies())
            buf = strat(buf)
        return bytes(buf)

    def batch(self, data: bytes, count: int, *, max_stack: int = 5) -> List[bytes]:
        return [self.mutate(data, max_stack=max_stack) for _ in range(count)]


class TypedMutator:
    """Value-aware mutation of ABI-typed argument tuples.

    Produces boundary and overflow candidates that are the usual triggers for
    arithmetic, access-control and accounting bugs in contracts.
    """

    ZERO_ADDR = "0x" + "00" * 20
    MAX_ADDR = "0x" + "ff" * 20

    def __init__(self, seed: int = 0):
        self.rng = random.Random(seed)

    def _mutate_uint(self, bits: int) -> int:
        top = (1 << bits) - 1
        return self.rng.choice([0, 1, top, top - 1, top // 2,
                                1 << (bits - 1), self.rng.randrange(top + 1)])

    def _mutate_int(self, bits: int) -> int:
        half = 1 << (bits - 1)
        return self.rng.choice([0, 1, -1, half - 1, -half,
                                self.rng.randrange(-half, half)])

    def _mutate_bytes(self) -> bytes:
        n = self.rng.choice([0, 1, 32, 33, 64, self.rng.randrange(0, 96)])
        return bytes(self.rng.randrange(256) for _ in range(n))

    def mutate_value(self, abi_type: str) -> Any:
        t = abi_type
        if t.startswith("uint"):
            return self._mutate_uint(int(t[4:] or 256))
        if t.startswith("int"):
            return self._mutate_int(int(t[3:] or 256))
        if t == "address":
            return self.rng.choice([self.ZERO_ADDR, self.MAX_ADDR,
                                    "0x" + "".join(self.rng.choice("0123456789abcdef")
                                                   for _ in range(40))])
        if t == "bool":
            return self.rng.random() < 0.5
        if t in ("bytes", "string"):
            raw = self._mutate_bytes()
            return raw.decode("latin-1") if t == "string" else raw
        if t.startswith("bytes"):
            return self._mutate_bytes()[:int(t[5:])]
        if t.endswith("[]"):
            base = t[:-2]
            return [self.mutate_value(base) for _ in range(self.rng.randint(0, 3))]
        # Unknown type: fall back to a uint256-ish integer.
        return self._mutate_uint(256)

    def mutate_args(self, abi_types: Sequence[str]) -> List[Any]:
        return [self.mutate_value(t) for t in abi_types]


# ---------------------------------------------------------------------------
# Corpus + crash de-duplication (binary fuzzer support)
# ---------------------------------------------------------------------------
@dataclass
class Corpus:
    """A growing set of interesting inputs, de-duplicated by content hash."""

    inputs: List[bytes] = field(default_factory=list)
    _hashes: set = field(default_factory=set)

    def add(self, data: bytes) -> bool:
        h = hashlib.blake2b(data, digest_size=16).digest()
        if h in self._hashes:
            return False
        self._hashes.add(h)
        self.inputs.append(data)
        return True

    def seed_from_dir(self, directory: str, *, limit: int = 256) -> int:
        added = 0
        if not os.path.isdir(directory):
            return 0
        for name in sorted(os.listdir(directory))[:limit]:
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    if self.add(fh.read()):
                        added += 1
        return added

    def sample(self, rng: random.Random) -> bytes:
        if not self.inputs:
            return b"\x00"
        return rng.choice(self.inputs)

    def __len__(self) -> int:
        return len(self.inputs)


@dataclass
class CrashInfo:
    """A single distinct crash observation."""

    signal: int
    signature: str
    sample_input: bytes
    stderr_excerpt: str = ""

    @property
    def key(self) -> str:
        return f"{self.signal}:{self.signature}"


class CrashBucket:
    """De-duplicates crashes so triage reports unique defects, not every hit."""

    def __init__(self) -> None:
        self._seen: Dict[str, CrashInfo] = {}

    def record(self, crash: CrashInfo) -> bool:
        if crash.key in self._seen:
            return False
        self._seen[crash.key] = crash
        return True

    @property
    def unique(self) -> List[CrashInfo]:
        return list(self._seen.values())

    @staticmethod
    def signature_from_stderr(stderr: str) -> str:
        """A stable short signature from the most relevant stderr line."""
        keywords = ("AddressSanitizer", "SUMMARY", "runtime error", "panic",
                    "Assertion", "segmentation", "buffer overflow", "abort")
        for line in stderr.splitlines():
            if any(k.lower() in line.lower() for k in keywords):
                return hashlib.blake2b(line.strip().encode(), digest_size=6).hexdigest()
        # Fall back to a hash of the last non-empty line.
        tail = next((ln for ln in reversed(stderr.splitlines()) if ln.strip()), "")
        return hashlib.blake2b(tail.encode(), digest_size=6).hexdigest()
