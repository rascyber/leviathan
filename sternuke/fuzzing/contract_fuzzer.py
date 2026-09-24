# -*- coding: utf-8 -*-
"""
sternuke.fuzzing.contract_fuzzer
================================

ABI-aware, property-based smart-contract fuzzing against a **local** node.

Given a deployed contract on a local test node (anvil / hardhat / ganache) and
its ABI, the fuzzer:

1. mutates ABI-typed arguments for each state-changing function
   (via :class:`TypedMutator`) and submits them,
2. after each call, re-evaluates a set of *property* functions - boolean
   view functions whose name marks an invariant (``echidna_*`` / ``invariant_*``
   / ``prop_*``), the convention popularised by Echidna/Foundry,
3. reports an invariant break when a property that held at the start returns
   ``false``, or reverts, after fuzzing.

It speaks raw JSON-RPC over ``aiohttp`` - no web3 dependency - and refuses any
non-local RPC endpoint by default (see :mod:`sternuke.fuzzing.guards`). It only
drives contracts you deployed to a node you control.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

try:
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None

from ..engine import Finding
from .abi import AbiError, encode_call, function_selector, parse_signature
from .guards import assert_local_rpc
from .mutator import TypedMutator

Logger = Callable[[str], None]

# Property functions are boolean view functions whose name marks an invariant.
_PROPERTY_PREFIXES = ("echidna_", "invariant_", "prop_")


@dataclass
class AbiFunction:
    """A single callable entry recovered from an ABI or signature list."""

    name: str
    inputs: List[str]
    mutating: bool = True          # False for view/pure
    outputs: List[str] = field(default_factory=list)

    @property
    def signature(self) -> str:
        return f"{self.name}({','.join(self.inputs)})"

    @property
    def is_property(self) -> bool:
        return (self.name.startswith(_PROPERTY_PREFIXES)
                and not self.inputs and self.outputs == ["bool"])


@dataclass
class ContractFuzzReport:
    calls: int = 0
    reverts: int = 0
    broken_properties: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


class JsonRpcClient:
    """A tiny async JSON-RPC 2.0 client for a local Ethereum node."""

    def __init__(self, url: str, *, timeout: float = 20.0,
                 logger: Optional[Logger] = None):
        if aiohttp is None:
            raise RuntimeError("aiohttp is required for contract fuzzing")
        self.url = url
        self.timeout = timeout
        self._log = logger or (lambda msg: None)
        self._id = 0
        self._session: Optional["aiohttp.ClientSession"] = None

    async def __aenter__(self) -> "JsonRpcClient":
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout))
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()

    async def call(self, method: str, params: List[Any]) -> Dict[str, Any]:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        assert self._session is not None
        async with self._session.post(self.url, json=payload) as resp:
            return await resp.json()

    async def eth_call(self, to: str, data: str, *, frm: Optional[str] = None
                       ) -> Dict[str, Any]:
        tx = {"to": to, "data": data}
        if frm:
            tx["from"] = frm
        return await self.call("eth_call", [tx, "latest"])

    async def eth_send(self, to: str, data: str, frm: str) -> Dict[str, Any]:
        tx = {"to": to, "data": data, "from": frm, "gas": "0x2dc6c0"}
        return await self.call("eth_sendTransaction", [tx])

    async def accounts(self) -> List[str]:
        res = await self.call("eth_accounts", [])
        return res.get("result", []) or []


class ContractFuzzer:
    """Property-based ABI fuzzer for a contract on a local node."""

    def __init__(self, rpc_url: str, contract_address: str, *,
                 functions: Sequence[AbiFunction],
                 sender: Optional[str] = None,
                 max_calls: int = 400, seed: int = 0,
                 allow_remote: bool = False,
                 logger: Optional[Logger] = None):
        # Guard: refuse non-local RPC endpoints unless explicitly overridden.
        self.rpc_url = assert_local_rpc(rpc_url, allow_remote=allow_remote)
        self.address = contract_address
        self.sender = sender
        self.max_calls = max_calls
        self.rng = random.Random(seed)
        self.mutator = TypedMutator(seed=seed)
        self._log = logger or (lambda msg: None)
        self.mutating = [f for f in functions if f.mutating and not f.is_property]
        self.properties = [f for f in functions if f.is_property]

    # -- ABI ingest ----------------------------------------------------------
    @staticmethod
    def functions_from_abi(abi: Sequence[Dict[str, Any]]) -> List[AbiFunction]:
        """Build the callable list from a standard JSON ABI array."""
        out: List[AbiFunction] = []
        for entry in abi:
            if entry.get("type") != "function":
                continue
            inputs = [i["type"] for i in entry.get("inputs", [])]
            outputs = [o["type"] for o in entry.get("outputs", [])]
            mutating = entry.get("stateMutability", "nonpayable") not in ("view", "pure")
            out.append(AbiFunction(entry["name"], inputs, mutating, outputs))
        return out

    @staticmethod
    def functions_from_signatures(signatures: Sequence[str]) -> List[AbiFunction]:
        """Build callables from bare signatures; ``prop_*() -> bool`` inferred."""
        out: List[AbiFunction] = []
        for sig in signatures:
            name, types = parse_signature(sig)
            is_prop = name.startswith(_PROPERTY_PREFIXES)
            out.append(AbiFunction(name, types, mutating=not is_prop,
                                   outputs=["bool"] if is_prop else []))
        return out

    # -- property evaluation -------------------------------------------------
    @staticmethod
    def _decode_bool(result_hex: Optional[str]) -> Optional[bool]:
        if not result_hex or result_hex == "0x":
            return None
        try:
            return int(result_hex, 16) != 0
        except ValueError:
            return None

    async def _check_properties(self, client: JsonRpcClient) -> Dict[str, Optional[bool]]:
        states: Dict[str, Optional[bool]] = {}
        for prop in self.properties:
            data = "0x" + function_selector(prop.signature).hex()
            resp = await client.eth_call(self.address, data, frm=self.sender)
            if "error" in resp:
                states[prop.name] = None  # reverted / unavailable
            else:
                states[prop.name] = self._decode_bool(resp.get("result"))
        return states

    # -- campaign ------------------------------------------------------------
    async def run(self) -> ContractFuzzReport:
        report = ContractFuzzReport()
        async with JsonRpcClient(self.rpc_url, logger=self._log) as client:
            if self.sender is None:
                accts = await client.accounts()
                self.sender = accts[0] if accts else None
                if self.sender:
                    self._log(f"[ctfuzz] using sender {self.sender}")

            baseline = await self._check_properties(client)
            held = {k for k, v in baseline.items() if v is True}
            self._log(f"[ctfuzz] {len(held)} property invariant(s) hold at baseline")

            for _ in range(self.max_calls):
                if not self.mutating:
                    break
                fn = self.rng.choice(self.mutating)
                try:
                    args = self.mutator.mutate_args(fn.inputs)
                    data = "0x" + encode_call(fn.signature, args).hex()
                except AbiError:
                    continue  # skip functions we cannot encode
                if self.sender:
                    resp = await client.eth_send(self.address, data, self.sender)
                else:
                    resp = await client.eth_call(self.address, data)
                report.calls += 1
                if "error" in resp:
                    report.reverts += 1

                # Re-evaluate invariants that held at baseline.
                current = await self._check_properties(client)
                for name in list(held):
                    if current.get(name) is False or current.get(name) is None:
                        if name not in report.broken_properties:
                            report.broken_properties.append(name)
                            report.findings.append(self._property_finding(name, fn, args))
                            self._log(f"[ctfuzz] INVARIANT BROKEN: {name} after {fn.name}")
                        held.discard(name)
                if not held:
                    break

        self._log(f"[ctfuzz] done: {report.calls} call(s), {report.reverts} revert(s), "
                  f"{len(report.broken_properties)} broken invariant(s)")
        return report

    def _property_finding(self, prop: str, fn: AbiFunction, args: Sequence[Any]) -> Finding:
        return Finding(
            rule_id=f"ctfuzz-invariant-{prop}".lower(),
            name=f"Broken invariant '{prop}'",
            severity="critical",
            target=self.address,
            matched_at=f"{self.address}::{prop}",
            evidence=f"invariant failed after {fn.name}({', '.join(map(str, args))})"[:300],
            description=f"Property '{prop}' held before fuzzing but returned false "
                        f"(or reverted) after calling {fn.signature}. This indicates "
                        f"a state the contract's invariants should forbid.",
            remediation="Reproduce the call sequence against the local node, then "
                        "add the missing precondition/accounting check.",
            tags=["blockchain", "fuzzing", "invariant", "property"],
        )
