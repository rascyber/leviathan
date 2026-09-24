# -*- coding: utf-8 -*-
"""
sternuke.cognitive
==================

Advanced multi-domain cognitive modules that sit on top of the stateful engine.

Web domain - :class:`BusinessLogicMutator`
    Given a stateful handler such as ``/api/v1/cart/checkout``, it generates a
    *sequence* of interaction steps that probe for business-logic flaws:
    parameter pollution (negative / zero / duplicated quantities), authorization
    bypass, and race conditions. The sequence is executed by
    :class:`sternuke.state_engine.StatefulChainEngine`, so the tests are stateful
    and dependency-aware rather than isolated requests.

Blockchain domain - :class:`CrossContractAnalyzer`
    Extends the static analysis to map *cross-contract* interactions. It builds a
    graph of external calls (``call`` / ``delegatecall`` / low-level sends, and
    Solana CPIs) and flags the structural discrepancy where a contract writes to
    its own state *after* an external value-transfer/execution vector - the shape
    of a reentrancy or flash-loan-preparation weakness.

Everything here is analysis and test *planning*. The blockchain side is purely
static; the web side emits assessment steps that run under the framework's
existing throttles.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .engine import Finding
from .state_engine import Extractor, InteractionStep

Logger = Callable[[str], None]


# ===========================================================================
# Web: business-logic mutation loop
# ===========================================================================
class BusinessLogicMutator:
    """Plans stateful business-logic test sequences for an endpoint.

    The planner is deliberately conservative: it mutates *client-supplied
    business parameters* (quantity, amount, price, ids) into boundary values and
    schedules a bounded race probe. It never fabricates destructive payloads;
    the findings come from the server accepting a value it should have rejected.
    """

    # Parameters whose sign/range the server should validate.
    NUMERIC_PARAMS = ("quantity", "qty", "amount", "count", "price", "total",
                      "balance", "credit", "points")
    OWNERSHIP_PARAMS = ("id", "user_id", "account_id", "order_id", "cart_id",
                        "owner", "uid")

    def __init__(self, logger: Optional[Logger] = None) -> None:
        self._log = logger or (lambda msg: None)

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _is_numeric_param(key: str) -> bool:
        k = key.lower()
        return any(tok in k for tok in BusinessLogicMutator.NUMERIC_PARAMS)

    @staticmethod
    def _is_ownership_param(key: str) -> bool:
        k = key.lower()
        return any(k == tok or k.endswith("_" + tok)
                   for tok in BusinessLogicMutator.OWNERSHIP_PARAMS)

    @staticmethod
    def _encode_body(params: Dict[str, str]) -> str:
        return "&".join(f"{k}={v}" for k, v in params.items())

    # -- planning ------------------------------------------------------------
    def plan(self, path: str, params: Dict[str, str], *, method: str = "POST",
             auth_header: Optional[Dict[str, str]] = None,
             low_priv_token: Optional[str] = None) -> List[InteractionStep]:
        """Return an ordered list of :class:`InteractionStep` probes.

        Parameters
        ----------
        path : the endpoint under test (e.g. ``/api/v1/cart/checkout``).
        params : a baseline set of valid business parameters.
        auth_header : headers establishing the *authorised* session.
        low_priv_token : optional bearer token for an authorization-bypass probe.
        """
        steps: List[InteractionStep] = []
        headers = dict(auth_header or {})
        expect_ok = [200, 201, 204]

        # 1) Baseline: capture a normal, valid transaction for comparison.
        steps.append(InteractionStep(
            name="baseline",
            method=method, path=path, headers=headers,
            body=self._encode_body(params),
            expect_status=expect_ok,
            extract=[Extractor("txn_ref", "json", "id"),
                     Extractor("csrf", "regex", r'name="csrf"\s+value="([^"]+)"')],
            note="Baseline valid transaction used as a behavioural reference.",
        ))

        # 2) Parameter pollution: negative / zero / duplicated numeric fields.
        for key, value in params.items():
            if not self._is_numeric_param(key):
                continue
            for label, mutant in (("negative", "-1"), ("zero", "0")):
                mutated = dict(params)
                mutated[key] = mutant
                steps.append(InteractionStep(
                    name=f"pollute_{key}_{label}",
                    method=method, path=path, headers=headers,
                    body=self._encode_body(mutated),
                    # A well-behaved server rejects these; a 2xx is suspicious.
                    expect_status=[400, 409, 422],
                    success_markers=["\"status\":\"ok\"", "confirmed", "success"],
                    note=f"Server should reject {label} '{key}'; acceptance implies "
                         "missing sign/range validation.",
                ))
            # Duplicate-parameter pollution (last-wins vs first-wins confusion).
            dup_body = self._encode_body(params) + f"&{key}=-1"
            steps.append(InteractionStep(
                name=f"pollute_{key}_duplicate",
                method=method, path=path, headers=headers, body=dup_body,
                expect_status=[400, 409, 422],
                success_markers=["confirmed", "success"],
                note=f"Duplicated '{key}' probes parser disagreement between "
                     "validation and business logic.",
                allow_self_correction=True,
            ))

        # 3) Authorization bypass: replay privileged action with weaker identity.
        if low_priv_token is not None:
            lp_headers = dict(headers)
            lp_headers["Authorization"] = f"Bearer {low_priv_token}"
            steps.append(InteractionStep(
                name="authz_low_priv_replay",
                method=method, path=path, headers=lp_headers,
                body=self._encode_body(params),
                expect_status=[401, 403],
                success_markers=["confirmed", "success", "\"status\":\"ok\""],
                note="A low-privilege token completing a privileged action "
                     "indicates broken function-level authorization.",
            ))
        # Ownership swap: point the action at another object id.
        for key in list(params):
            if self._is_ownership_param(key):
                swapped = dict(params)
                swapped[key] = "{{txn_ref}}"  # reuse a captured id from baseline
                steps.append(InteractionStep(
                    name=f"authz_object_swap_{key}",
                    method=method, path=path, headers=headers,
                    body=self._encode_body(swapped),
                    expect_status=[401, 403, 404],
                    success_markers=["confirmed", "success"],
                    note=f"Acting on a different '{key}' probes IDOR / object-level "
                         "authorization.",
                ))

        # 4) Race condition: concurrent execution of the single-use action.
        steps.append(InteractionStep(
            name="race_double_execute",
            method=method, path=path, headers=headers,
            body=self._encode_body(params),
            expect_status=expect_ok,
            concurrency=5,
            note="Concurrent duplicates probe time-of-check/time-of-use races "
                 "on the shared resource (stock, balance, coupon).",
        ))

        self._log(f"[logic] planned {len(steps)} business-logic step(s) for {path}")
        return steps


# ===========================================================================
# Blockchain: cross-contract interaction & reentrancy mapping
# ===========================================================================
@dataclass
class ExternalCall:
    """A single external interaction observed in a function body."""

    kind: str            # call | delegatecall | staticcall | transfer | send | cpi
    target: str
    transfers_value: bool
    position: int        # character offset within the function body


@dataclass
class CallGraphNode:
    """Per-function view of external calls and subsequent state writes."""

    contract: str
    function: str
    language: str
    path: str
    external_calls: List[ExternalCall] = field(default_factory=list)
    state_write_positions: List[int] = field(default_factory=list)
    reentrancy_guarded: bool = False


class CrossContractAnalyzer:
    """Builds a cross-contract call graph and flags reentrancy-shaped flaws.

    The core heuristic (checks-effects-interactions): within a state-changing
    function, if a *state write* occurs at a character position *after* an
    external value-transfer call, the effect follows the interaction - the
    classic reentrancy / flash-loan-preparation footprint.
    """

    # Solidity external-interaction primitives.
    _SOL_CONTRACT = re.compile(r"\b(?:contract|library|interface)\s+([A-Za-z_]\w*)")
    _SOL_FUNC = re.compile(
        r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)"
        r"(?P<attrs>[^{;]*)\{", re.MULTILINE)
    _SOL_VALUE_CALL = re.compile(
        r"(?P<expr>[A-Za-z_]\w*(?:\[[^\]]*\])?)\.(?P<m>call|delegatecall|staticcall)"
        r"\s*(?:\{[^}]*value[^}]*\})?\s*\(", re.MULTILINE)
    _SOL_SEND = re.compile(r"(?P<expr>[A-Za-z_]\w*(?:\[[^\]]*\])?)\.(?P<m>transfer|send)\s*\(")
    _SOL_STATE_WRITE = re.compile(
        r"^\s*(?P<lhs>[A-Za-z_]\w*(?:\[[^\]]*\])?)\s*(?:=|[-+*/]=)\s*", re.MULTILINE)
    _GUARD_HINTS = ("nonReentrant", "reentrancyGuard", "_locked", "mutex")

    # Rust / Solana CPI primitives.
    _RS_FUNC = re.compile(r"\bfn\s+(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)[^{]*\{", re.MULTILINE)
    _RS_CPI = re.compile(r"\b(invoke|invoke_signed)\s*\(")
    _RS_STATE_WRITE = re.compile(
        r"\b(?:ctx\.accounts\.[A-Za-z_.]+|[A-Za-z_]\w*)\.(?:amount|balance|lamports"
        r"|state|data)\s*(?:=|[-+]=)")

    def __init__(self, logger: Optional[Logger] = None) -> None:
        self._log = logger or (lambda msg: None)

    # -- Solidity ------------------------------------------------------------
    def _function_bodies(self, code: str) -> List[Tuple[str, str, str]]:
        """Yield (function_name, attrs, body) by brace-matching each function."""
        out: List[Tuple[str, str, str]] = []
        for m in self._SOL_FUNC.finditer(code):
            start = m.end()  # position just after the opening brace
            depth = 1
            i = start
            while i < len(code) and depth > 0:
                ch = code[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                i += 1
            body = code[start:i - 1]
            out.append((m.group("name"), m.group("attrs") or "", body))
        return out

    def analyze_solidity(self, path: str, code: str) -> List[CallGraphNode]:
        contract = (self._SOL_CONTRACT.search(code) or [None, "UnknownContract"])[1] \
            if self._SOL_CONTRACT.search(code) else "UnknownContract"
        nodes: List[CallGraphNode] = []
        for fname, attrs, body in self._function_bodies(code):
            node = CallGraphNode(contract=contract, function=fname,
                                 language="solidity", path=path)
            node.reentrancy_guarded = any(g in attrs or g in body for g in self._GUARD_HINTS)
            for cm in self._SOL_VALUE_CALL.finditer(body):
                transfers = ".call" in cm.group(0) and "value" in cm.group(0)
                node.external_calls.append(ExternalCall(
                    kind=cm.group("m"), target=cm.group("expr"),
                    transfers_value=transfers or cm.group("m") == "delegatecall",
                    position=cm.start()))
            for sm in self._SOL_SEND.finditer(body):
                node.external_calls.append(ExternalCall(
                    kind=sm.group("m"), target=sm.group("expr"),
                    transfers_value=True, position=sm.start()))
            node.state_write_positions = [w.start() for w in self._SOL_STATE_WRITE.finditer(body)]
            nodes.append(node)
        return nodes

    # -- Rust / Solana -------------------------------------------------------
    def analyze_rust(self, path: str, code: str) -> List[CallGraphNode]:
        nodes: List[CallGraphNode] = []
        module = re.sub(r"\.rs$", "", path.rsplit("/", 1)[-1])
        for m in self._RS_FUNC.finditer(code):
            start = m.end()
            depth, i = 1, start
            while i < len(code) and depth > 0:
                if code[i] == "{":
                    depth += 1
                elif code[i] == "}":
                    depth -= 1
                i += 1
            body = code[start:i - 1]
            node = CallGraphNode(contract=module, function=m.group("name"),
                                 language="rust", path=path)
            for cm in self._RS_CPI.finditer(body):
                node.external_calls.append(ExternalCall(
                    kind="cpi", target=cm.group(1), transfers_value=True,
                    position=cm.start()))
            node.state_write_positions = [w.start() for w in self._RS_STATE_WRITE.finditer(body)]
            nodes.append(node)
        return nodes

    # -- graph + findings ----------------------------------------------------
    def analyze(self, path: str, code: str, language: str) -> List[CallGraphNode]:
        if language == "solidity":
            return self.analyze_solidity(path, code)
        if language == "rust":
            return self.analyze_rust(path, code)
        return []

    def findings(self, nodes: Sequence[CallGraphNode]) -> List[Finding]:
        """Flag functions where a state write follows an external value transfer."""
        results: List[Finding] = []
        for node in nodes:
            value_calls = [c for c in node.external_calls if c.transfers_value]
            if not value_calls or not node.state_write_positions:
                continue
            first_transfer = min(c.position for c in value_calls)
            writes_after = [p for p in node.state_write_positions if p > first_transfer]
            if not writes_after:
                continue
            severity = "medium" if node.reentrancy_guarded else "critical"
            guard_note = (" A reentrancy guard was detected, which may mitigate this, "
                          "but the ordering still violates checks-effects-interactions."
                          if node.reentrancy_guarded else "")
            call_targets = ", ".join(sorted({c.target + "." + c.kind for c in value_calls}))
            results.append(Finding(
                rule_id=f"xcontract-reentrancy-{node.contract}-{node.function}".lower(),
                name=f"State write after external transfer in "
                     f"{node.contract}.{node.function}",
                severity=severity,
                target=node.path,
                matched_at=f"{node.path}::{node.function}",
                evidence=f"external value vector via [{call_targets}] precedes "
                         f"{len(writes_after)} state write(s)",
                description="A state-changing write occurs after an external "
                            "value-transfer/execution call, matching the reentrancy / "
                            "flash-loan-preparation pattern." + guard_note,
                remediation="Apply checks-effects-interactions: perform all state "
                            "updates before external calls, and add a reentrancy guard.",
                tags=["blockchain", "reentrancy", "cross-contract", node.language],
            ))
        self._log(f"[xcontract] flagged {len(results)} reentrancy-shaped finding(s)")
        return results

    def call_graph_summary(self, nodes: Sequence[CallGraphNode]) -> Dict[str, List[str]]:
        """Return a simple contract.function -> [external targets] adjacency map."""
        graph: Dict[str, List[str]] = {}
        for node in nodes:
            if node.external_calls:
                key = f"{node.contract}.{node.function}"
                graph[key] = sorted({f"{c.target}.{c.kind}" for c in node.external_calls})
        return graph
