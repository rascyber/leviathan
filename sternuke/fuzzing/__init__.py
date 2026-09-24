# -*- coding: utf-8 -*-
"""
sternuke.fuzzing
================

Automated payload-mutation and fuzzing subsystem for sternuke.

Three domain drivers share a common mutation core and a strict, local-by-default
scope guard:

* :class:`WebFuzzer`      - mutates web/API parameters under the engine's
  :class:`~sternuke.engine.ScanPolicy` throttles.
* :class:`ContractFuzzer` - ABI-aware, property/invariant-based fuzzing against a
  local Ethereum test node (no web3 dependency; keccak/ABI implemented locally).
* :class:`BinaryFuzzer`   - bounded black-box mutational fuzzing of a local
  executable, with crash triage and de-duplication.

Every driver enforces :mod:`sternuke.fuzzing.guards`: fuzzing stays pointed at
local / operator-controlled targets unless the operator explicitly opts in.
"""

from __future__ import annotations

from .mutator import ByteMutator, Corpus, CrashBucket, CrashInfo, TypedMutator
from .keccak import keccak256, keccak_hex
from .abi import (
    AbiError, encode_call, encode_parameters, function_selector, parse_signature,
)
from .guards import (
    ScopeError, assert_local_executable, assert_local_rpc, assert_web_scope,
)
from .web_fuzzer import PayloadMutator, WebFuzzBudget, WebFuzzer, WebFuzzReport
from .contract_fuzzer import (
    AbiFunction, ContractFuzzer, ContractFuzzReport, JsonRpcClient,
)
from .binary_fuzzer import (
    BinaryFuzzer, BinaryFuzzReport, FuzzBudget,
)

__all__ = [
    "ByteMutator", "TypedMutator", "Corpus", "CrashBucket", "CrashInfo",
    "keccak256", "keccak_hex",
    "AbiError", "encode_call", "encode_parameters", "function_selector",
    "parse_signature",
    "ScopeError", "assert_local_executable", "assert_local_rpc", "assert_web_scope",
    "PayloadMutator", "WebFuzzBudget", "WebFuzzer", "WebFuzzReport",
    "AbiFunction", "ContractFuzzer", "ContractFuzzReport", "JsonRpcClient",
    "BinaryFuzzer", "BinaryFuzzReport", "FuzzBudget",
]
