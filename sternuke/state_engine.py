# -*- coding: utf-8 -*-
"""
sternuke.state_engine
=====================

Stateful interaction, chaining, and self-correction for sternuke.

Where :mod:`sternuke.engine` fires independent, stateless requests, this module
adds the machinery a *cognitive* assessment agent needs:

* :class:`SessionState` - a Session State Manager tracking cookies, headers,
  nonces and arbitrary captured variables across a sequence of interactions.
* :class:`Extractor` - pulls output fields (tokens, ids, nonces) out of a
  response so they can be piped into later steps.
* :class:`InteractionStep` / :class:`DependencyGraph` - a Dependency Graph
  Explorer that captures Step A's outputs and injects them into Step B's
  parameters, executing steps in dependency order.
* :class:`StatefulChainEngine` - runs a chain over the shared
  :class:`~sternuke.engine.AsyncHttpClient`, honouring the same
  :class:`~sternuke.engine.ScanPolicy` throttles.
* :class:`SelfCorrectionLoop` - a bounded "refusal to fail" loop: when a step
  is blocked (403/400/406/reverted), the failure context is analysed (by the
  local model, with deterministic fallbacks) to produce alternative *encodings*
  of the same test input, which are re-injected up to a strict attempt cap.

The self-correction loop is an assessment-accuracy feature: its job is to tell
"the app is actually safe" apart from "a filter rejected a malformed probe" on
systems you are authorised to test. It stays within the active
:class:`ScanPolicy` limits and contains no stealth/anti-monitoring behaviour.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

from .engine import AsyncHttpClient, Finding, HttpResponse, ScanPolicy

# Optional AI hook; imported lazily-safe so state_engine works without a model.
try:
    from .ai_agent import LocalModelClient
except Exception:  # pragma: no cover
    LocalModelClient = None  # type: ignore


Logger = Callable[[str], None]
_TEMPLATE_RE = re.compile(r"\{\{\s*([A-Za-z0-9_.]+)\s*\}\}")


# ===========================================================================
# Session state
# ===========================================================================
@dataclass
class SessionState:
    """Mutable state threaded through a chain of interactions.

    ``variables`` holds captured outputs (tokens, ids, nonces). ``cookies`` and
    ``headers`` are merged into every outgoing request. ``history`` records the
    responses seen so far for post-hoc analysis.
    """

    variables: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    history: List[HttpResponse] = field(default_factory=list)

    def context(self) -> Dict[str, str]:
        """Flat name->value map used for ``{{template}}`` resolution."""
        ctx: Dict[str, str] = {}
        ctx.update(self.cookies)
        ctx.update(self.variables)
        return ctx

    def update_from_response(self, resp: HttpResponse) -> None:
        """Absorb Set-Cookie headers and record the response in history."""
        self.history.append(resp)
        set_cookie = resp.headers.get("Set-Cookie") or resp.headers.get("set-cookie")
        if set_cookie:
            for part in set_cookie.split(","):
                m = re.match(r"\s*([^=;]+)=([^;]+)", part)
                if m:
                    self.cookies[m.group(1).strip()] = m.group(2).strip()

    def cookie_header(self) -> Dict[str, str]:
        if not self.cookies:
            return {}
        return {"Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())}


# ===========================================================================
# Extraction
# ===========================================================================
@dataclass
class Extractor:
    """Captures a value from a response into ``name`` in the session.

    Supported ``kind`` values:

    * ``regex``  - first capture group of ``expr`` against body (or ``part``).
    * ``json``   - dotted path lookup into a JSON body (e.g. ``data.token``).
    * ``header`` - value of the header named by ``expr``.
    """

    name: str
    kind: str = "regex"
    expr: str = ""
    part: str = "body"

    def apply(self, resp: HttpResponse) -> Optional[str]:
        if self.kind == "header":
            for k, v in resp.headers.items():
                if k.lower() == self.expr.lower():
                    return v
            return None
        if self.kind == "json":
            try:
                data: Any = json.loads(resp.body)
            except (json.JSONDecodeError, ValueError):
                return None
            for key in self.expr.split("."):
                if isinstance(data, dict) and key in data:
                    data = data[key]
                elif isinstance(data, list) and key.isdigit() and int(key) < len(data):
                    data = data[int(key)]
                else:
                    return None
            return str(data)
        # default: regex
        text = resp.header_blob if self.part == "header" else resp.body
        m = re.search(self.expr, text, re.DOTALL)
        if not m:
            return None
        return m.group(1) if m.groups() else m.group(0)


# ===========================================================================
# Interaction steps + dependency graph
# ===========================================================================
@dataclass
class InteractionStep:
    """One node in an interaction chain.

    Template fields (``path``, ``headers`` values, ``body``) may reference
    captured variables with ``{{name}}`` syntax. ``extract`` defines what this
    step contributes to the session for downstream steps.
    """

    name: str
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    extract: List[Extractor] = field(default_factory=list)
    expect_status: Optional[List[int]] = None       # statuses considered "normal"
    success_markers: List[str] = field(default_factory=list)  # body markers => finding
    concurrency: int = 1                             # >1 => fire concurrently (race test)
    allow_self_correction: bool = False
    note: str = ""

    def produced(self) -> List[str]:
        return [e.name for e in self.extract]

    def consumed(self) -> List[str]:
        blob = " ".join([self.path, self.body or "", *self.headers.values()])
        return sorted({m.group(1).split(".")[0] for m in _TEMPLATE_RE.finditer(blob)})


class DependencyGraph:
    """Orders interaction steps so producers run before consumers.

    Builds a DAG from the variables each step produces vs. consumes and returns
    a topologically sorted execution order. Steps whose dependencies are all
    externally supplied (present in ``seed_vars``) have no inbound edges.
    """

    def __init__(self, steps: Sequence[InteractionStep],
                 seed_vars: Optional[Sequence[str]] = None) -> None:
        self.steps: List[InteractionStep] = list(steps)
        self.seed_vars = set(seed_vars or [])
        self._producer: Dict[str, int] = {}
        for idx, step in enumerate(self.steps):
            for var in step.produced():
                self._producer[var] = idx

    def edges(self) -> List[Tuple[int, int]]:
        edges: List[Tuple[int, int]] = []
        for idx, step in enumerate(self.steps):
            for var in step.consumed():
                if var in self.seed_vars:
                    continue
                src = self._producer.get(var)
                if src is not None and src != idx:
                    edges.append((src, idx))
        return edges

    def topological_order(self) -> List[InteractionStep]:
        n = len(self.steps)
        indeg = [0] * n
        adj: Dict[int, List[int]] = {i: [] for i in range(n)}
        for src, dst in self.edges():
            adj[src].append(dst)
            indeg[dst] += 1
        ready = [i for i in range(n) if indeg[i] == 0]
        order: List[int] = []
        while ready:
            node = ready.pop(0)
            order.append(node)
            for nxt in adj[node]:
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    ready.append(nxt)
        if len(order) != n:
            # Cycle: fall back to declaration order but do not crash.
            remaining = [i for i in range(n) if i not in order]
            order.extend(remaining)
        return [self.steps[i] for i in order]


# ===========================================================================
# Chain result
# ===========================================================================
@dataclass
class StepResult:
    step: str
    status: Optional[int]
    url: str
    extracted: Dict[str, str] = field(default_factory=dict)
    corrected: bool = False
    attempts: int = 1


@dataclass
class ChainResult:
    name: str
    steps: List[StepResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    final_state: Optional[SessionState] = None


# ===========================================================================
# Self-correction ("refusal to fail")
# ===========================================================================
class SelfCorrectionLoop:
    """Bounded adaptive-retry helper for blocked assessment probes.

    On a blocked/failed step it produces alternative *representations* of the
    probe token so the engine can distinguish a genuine control from a naive
    input filter. Attempts are hard-capped and every retry still passes through
    the throttled HTTP client, so this never becomes an unbounded or high-rate
    loop.
    """

    BLOCK_STATUSES = {400, 401, 403, 405, 406, 422, 429, 501}
    REVERT_MARKERS = ("revert", "execution reverted", "VM Exception")

    def __init__(self, model: Optional["LocalModelClient"] = None,
                 max_attempts: int = 3, logger: Optional[Logger] = None) -> None:
        self.model = model
        self.max_attempts = max(1, max_attempts)
        self._log = logger or (lambda msg: None)

    @classmethod
    def is_blocked(cls, resp: Optional[HttpResponse]) -> bool:
        if resp is None:
            return True
        if resp.status in cls.BLOCK_STATUSES:
            return True
        low = resp.body.lower()
        return any(marker.lower() in low for marker in cls.REVERT_MARKERS)

    # -- deterministic encoding variants (used with or without the model) ----
    @staticmethod
    def _encoding_variants(token: str) -> List[str]:
        variants = [
            quote(token, safe=""),                    # percent-encode
            quote(quote(token, safe=""), safe=""),    # double percent-encode
            token.replace(" ", "/**/"),               # whitespace alternative
            "".join(c.swapcase() if c.isalpha() else c for c in token),  # case
            token.encode("unicode_escape").decode("ascii"),              # \x escapes
        ]
        # De-duplicate while keeping order and dropping no-ops.
        seen, out = set(), []
        for v in variants:
            if v and v != token and v not in seen:
                seen.add(v)
                out.append(v)
        return out

    async def propose_mutations(self, step: InteractionStep,
                                resp: Optional[HttpResponse]) -> List[str]:
        """Return candidate replacement values for the step's probe token.

        Prefers the local model's analysis of *why* the probe was blocked, then
        falls back to deterministic encoding variants. Both are advisory - the
        caller re-runs the same logical test, only re-encoded.
        """
        token = step.body or step.path
        deterministic = self._encoding_variants(token)
        if self.model is None:
            return deterministic
        status = resp.status if resp else "no-response"
        snippet = (resp.body[:400] if resp else "")
        system = (
            "You assist an authorised security assessment. A benign probe was "
            "rejected by a server-side filter. Explain briefly which validation "
            "likely blocked it, then output a JSON array of alternative, "
            "equivalent encodings of the SAME input to test filter robustness. "
            "Do not add destructive payloads."
        )
        user = (f"HTTP status: {status}\nProbe: {token}\nResponse snippet:\n{snippet}\n"
                "Return: {\"encodings\": [\"...\"]}")
        raw = await self.model.chat(system, user)
        if not raw:
            return deterministic
        try:
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            data = json.loads(m.group(0)) if m else {}
            model_variants = [str(x) for x in data.get("encodings", []) if str(x) != token]
        except (json.JSONDecodeError, AttributeError, TypeError):
            model_variants = []
        # Merge, model-first, capped at max_attempts.
        merged: List[str] = []
        for v in model_variants + deterministic:
            if v not in merged:
                merged.append(v)
        return merged[: self.max_attempts]


# ===========================================================================
# Stateful chain engine
# ===========================================================================
class StatefulChainEngine:
    """Executes an interaction chain with shared session state.

    Integrates directly with the existing pipeline: it borrows an
    :class:`AsyncHttpClient` (and therefore the active :class:`ScanPolicy`
    throttles) and yields :class:`Finding` objects compatible with the rest of
    sternuke.
    """

    def __init__(self, policy: ScanPolicy,
                 model: Optional["LocalModelClient"] = None,
                 logger: Optional[Logger] = None,
                 max_correction_attempts: int = 3) -> None:
        self.policy = policy
        self._log = logger or (lambda msg: None)
        self.corrector = SelfCorrectionLoop(model, max_correction_attempts, logger)

    # -- template rendering --------------------------------------------------
    @staticmethod
    def _render(template: str, ctx: Dict[str, str]) -> str:
        return _TEMPLATE_RE.sub(lambda m: ctx.get(m.group(1).split(".")[0], ""), template)

    def _build_request(self, base: str, step: InteractionStep,
                       state: SessionState) -> Tuple[str, Dict[str, str], Optional[str]]:
        ctx = state.context()
        path = self._render(step.path, ctx)
        url = base.rstrip("/") + (path if path.startswith("/") else "/" + path)
        headers = {k: self._render(v, ctx) for k, v in step.headers.items()}
        headers.update(state.headers)
        headers.update(state.cookie_header())
        body = self._render(step.body, ctx) if step.body is not None else None
        return url, headers, body

    # -- single step ---------------------------------------------------------
    async def _run_step(self, client: AsyncHttpClient, base: str,
                        step: InteractionStep, state: SessionState) -> StepResult:
        url, headers, body = self._build_request(base, step, state)
        resp = await client.request(step.method, url, headers=headers, data=body)
        attempts = 1
        corrected = False

        # "Refusal to fail": adapt encoding when a benign probe is filtered.
        if step.allow_self_correction and self.corrector.is_blocked(resp):
            self._log(f"[chain] step '{step.name}' blocked "
                      f"(status={resp.status if resp else 'none'}); self-correcting")
            for variant in await self.corrector.propose_mutations(step, resp):
                attempts += 1
                mutated = InteractionStep(**{**step.__dict__, "body": variant}) \
                    if step.body is not None else \
                    InteractionStep(**{**step.__dict__, "path": variant})
                v_url, v_headers, v_body = self._build_request(base, mutated, state)
                resp = await client.request(step.method, v_url, headers=v_headers, data=v_body)
                url = v_url
                if not self.corrector.is_blocked(resp):
                    corrected = True
                    self._log(f"[chain] step '{step.name}' passed the filter on "
                              f"attempt {attempts} via re-encoding")
                    break

        result = StepResult(step=step.name, status=(resp.status if resp else None),
                            url=url, corrected=corrected, attempts=attempts)
        if resp is not None:
            state.update_from_response(resp)
            for extractor in step.extract:
                value = extractor.apply(resp)
                if value is not None:
                    state.variables[extractor.name] = value
                    result.extracted[extractor.name] = value
        return result

    async def _run_race(self, client: AsyncHttpClient, base: str,
                        step: InteractionStep, state: SessionState) -> List[StepResult]:
        """Fire a step concurrently to probe for time-of-check/use races."""
        url, headers, body = self._build_request(base, step, state)
        n = min(step.concurrency, self.policy.per_host_concurrency)

        async def one() -> StepResult:
            resp = await client.request(step.method, url, headers=headers, data=body)
            if resp is not None:
                state.update_from_response(resp)
            return StepResult(step=step.name, status=(resp.status if resp else None), url=url)

        return list(await asyncio.gather(*[one() for _ in range(n)]))

    # -- full chain ----------------------------------------------------------
    async def run_chain(self, base: str, steps: Sequence[InteractionStep],
                        client: AsyncHttpClient, *, name: str = "chain",
                        seed_vars: Optional[Dict[str, str]] = None,
                        extra_headers: Optional[Dict[str, str]] = None,
                        memory=None) -> ChainResult:
        # Session headers (e.g. an authenticated cookie) applied to every step.
        state = SessionState(variables=dict(seed_vars or {}),
                             headers=dict(extra_headers or {}))
        graph = DependencyGraph(steps, seed_vars=list((seed_vars or {}).keys()))
        ordered = graph.topological_order()
        result = ChainResult(name=name)
        self._log(f"[chain] executing '{name}' with {len(ordered)} step(s)")

        for step in ordered:
            if step.concurrency > 1:
                race_results = await self._run_race(client, base, step, state)
                result.steps.extend(race_results)
                self._evaluate_race(step, race_results, base, result, memory)
            else:
                sr = await self._run_step(client, base, step, state)
                result.steps.append(sr)
                self._evaluate_step(step, sr, base, result, memory)

        result.final_state = state
        self._log(f"[chain] '{name}' complete: {len(result.findings)} finding(s)")
        return result

    # -- finding evaluation --------------------------------------------------
    def _evaluate_step(self, step: InteractionStep, sr: StepResult, base: str,
                       result: ChainResult, memory) -> None:
        resp = result.final_state.history[-1] if result.final_state and \
            result.final_state.history else None
        body = resp.body if resp else ""
        hit_marker = next((m for m in step.success_markers if m in body), None)
        unexpected = (step.expect_status is not None and sr.status is not None
                      and sr.status not in step.expect_status
                      and 200 <= sr.status < 300)
        if hit_marker or unexpected:
            finding = Finding(
                rule_id=f"logic-{step.name}",
                name=f"Business-logic anomaly in step '{step.name}'",
                severity="high",
                target=base,
                matched_at=sr.url,
                evidence=(f"marker={hit_marker}" if hit_marker
                          else f"unexpected success status {sr.status}"),
                description=step.note or "A stateful interaction produced an "
                            "unexpected authorised/success outcome.",
                tags=["web", "business-logic", "stateful"],
            )
            result.findings.append(finding)
            self._remember(memory, finding, step)

    def _evaluate_race(self, step: InteractionStep, results: List[StepResult],
                       base: str, result: ChainResult, memory) -> None:
        successes = [r for r in results if r.status is not None and 200 <= r.status < 300]
        # More than one success on a supposedly single-use action hints at a race.
        if len(successes) > 1 and step.expect_status is not None:
            allowed = sum(1 for r in successes if r.status in step.expect_status)
            if allowed > 1:
                finding = Finding(
                    rule_id=f"race-{step.name}",
                    name=f"Possible race condition in '{step.name}'",
                    severity="high",
                    target=base,
                    matched_at=results[0].url,
                    evidence=f"{allowed}/{len(results)} concurrent requests succeeded",
                    description=step.note or "Concurrent execution of a stateful "
                                "action produced multiple successful outcomes.",
                    tags=["web", "business-logic", "race-condition"],
                )
                result.findings.append(finding)
                self._remember(memory, finding, step)

    @staticmethod
    def _remember(memory, finding: Finding, step: InteractionStep) -> None:
        if memory is None:
            return
        try:
            memory.remember_finding(
                title=finding.name, text=finding.description, domain="web",
                tech=finding.tags, severity=finding.severity, strategy=step.note,
            )
        except Exception:  # noqa: BLE001 - memory is best-effort
            pass


# ===========================================================================
# JSONPath-lite (dependency-free) for response extraction
# ===========================================================================
_JPATH_TOKEN = re.compile(r"([A-Za-z_][\w-]*)|\[(\d+)\]|\['([^']*)'\]|\[\"([^\"]*)\"\]")


def jsonpath_get(data: Any, path: str) -> Optional[Any]:
    """Resolve a dotted/bracketed path (e.g. ``data.items[0].token``).

    Supports object keys (dot or bracket notation) and numeric array indices.
    A leading ``$`` or ``$.`` is optional. Returns ``None`` if any segment
    cannot be resolved.
    """
    if path.startswith("$"):
        path = path[1:]
    path = path.lstrip(".")
    cursor: Any = data
    for m in _JPATH_TOKEN.finditer(path):
        key = m.group(1) or m.group(3) or m.group(4)
        idx = m.group(2)
        if idx is not None:
            if isinstance(cursor, (list, tuple)) and int(idx) < len(cursor):
                cursor = cursor[int(idx)]
            else:
                return None
        else:
            if isinstance(cursor, dict) and key in cursor:
                cursor = cursor[key]
            else:
                return None
    return cursor


# ===========================================================================
# Session vault
# ===========================================================================
class SessionStateManager:
    """In-memory session vault for a multi-step assessment.

    Tracks the credential material that stateful web flows depend on - cookies,
    JWTs, anti-CSRF tokens and dynamic nonces - alongside arbitrary captured
    variables. It merges the right material into outgoing requests and resolves
    ``{{variable}}`` templates from a single flat context.

    Everything lives in process memory only; nothing is written to disk or sent
    anywhere by this class.
    """

    def __init__(self) -> None:
        self.cookies: Dict[str, str] = {}
        self.jwts: Dict[str, str] = {}
        self.csrf_tokens: Dict[str, str] = {}
        self.nonces: Dict[str, int] = {}
        self.variables: Dict[str, str] = {}

    # -- credential setters --------------------------------------------------
    def set_cookie(self, name: str, value: str) -> None:
        self.cookies[name] = value

    def set_jwt(self, name: str, token: str) -> None:
        self.jwts[name] = token
        self.variables[name] = token

    def set_csrf(self, token: str, *, name: str = "csrf") -> None:
        self.csrf_tokens[name] = token
        self.variables[name] = token

    def set_nonce(self, name: str, value: int) -> None:
        self.nonces[name] = int(value)

    def next_nonce(self, name: str) -> int:
        """Increment and return a monotonic nonce (defaults to starting at 0)."""
        self.nonces[name] = self.nonces.get(name, -1) + 1
        self.variables[name] = str(self.nonces[name])
        return self.nonces[name]

    def put(self, key: str, value: str) -> None:
        self.variables[key] = value

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.variables.get(key, default)

    # -- ingestion from responses -------------------------------------------
    def ingest_response(self, resp: HttpResponse) -> None:
        """Absorb Set-Cookie headers and any bearer token echoed back."""
        for header_name, header_value in resp.headers.items():
            if header_name.lower() == "set-cookie":
                for part in header_value.split(","):
                    m = re.match(r"\s*([^=;]+)=([^;]+)", part)
                    if m:
                        self.set_cookie(m.group(1).strip(), m.group(2).strip())

    @staticmethod
    def decode_jwt(token: str) -> Dict[str, Any]:
        """Decode a JWT's header+payload WITHOUT verifying the signature.

        For inspection only (e.g. reading claims/algorithm during assessment);
        never treat the result as authenticated.
        """
        import base64
        parts = token.split(".")
        if len(parts) < 2:
            return {}

        def _b64(seg: str) -> Dict[str, Any]:
            pad = "=" * (-len(seg) % 4)
            try:
                return json.loads(base64.urlsafe_b64decode(seg + pad))
            except (ValueError, json.JSONDecodeError):
                return {}

        return {"header": _b64(parts[0]), "payload": _b64(parts[1])}

    # -- request material ----------------------------------------------------
    def cookie_header(self) -> Dict[str, str]:
        if not self.cookies:
            return {}
        return {"Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())}

    def context(self) -> Dict[str, str]:
        """Flat name->value map used for ``{{template}}`` resolution."""
        ctx: Dict[str, str] = {}
        ctx.update({k: str(v) for k, v in self.nonces.items()})
        ctx.update(self.cookies)
        ctx.update(self.csrf_tokens)
        ctx.update(self.jwts)
        ctx.update(self.variables)
        return ctx

    def resolve(self, template: str) -> str:
        """Substitute ``{{var}}`` placeholders from the vault context."""
        ctx = self.context()
        return _TEMPLATE_RE.sub(lambda m: ctx.get(m.group(1).split(".")[0], ""), template)

    def to_session_state(self) -> SessionState:
        """Export as a :class:`SessionState` for the StatefulChainEngine."""
        return SessionState(variables=dict(self.context()), cookies=dict(self.cookies))


# ===========================================================================
# Dependency-graph execution engine
# ===========================================================================
@dataclass
class ExtractionRule:
    """Captures a variable from a response into the session vault.

    ``source`` is one of ``body`` / ``header`` / ``status``. ``method`` is
    ``regex`` or ``jsonpath`` (``jsonpath`` applies to a JSON body). ``expr`` is
    the pattern/path; for a header source it is the header name.
    """

    name: str
    source: str = "body"
    method: str = "regex"
    expr: str = ""

    def apply(self, resp: HttpResponse) -> Optional[str]:
        if self.source == "status":
            return str(resp.status)
        if self.source == "header":
            for k, v in resp.headers.items():
                if k.lower() == self.expr.lower():
                    return v
            return None
        # body
        if self.method == "jsonpath":
            try:
                data = json.loads(resp.body)
            except (json.JSONDecodeError, ValueError):
                return None
            value = jsonpath_get(data, self.expr)
            return None if value is None else str(value)
        m = re.search(self.expr, resp.body, re.DOTALL)
        if not m:
            return None
        return m.group(1) if m.groups() else m.group(0)


@dataclass
class RequestSpec:
    """A single request node in a dependency graph.

    Template fields may reference vault variables with ``{{name}}``. ``inject``
    maps a variable name to an explicit target: ``header:X-CSRF-Token``,
    ``body:field`` (form/query style body), or ``path`` (substituted via the
    ``{{name}}`` placeholder already present in ``path``).
    """

    name: str
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    extract: List[ExtractionRule] = field(default_factory=list)
    inject: Dict[str, str] = field(default_factory=dict)

    def produced(self) -> List[str]:
        return [e.name for e in self.extract]

    def consumed(self) -> List[str]:
        blob = " ".join([self.path, self.body or "", *self.headers.values(),
                         *self.inject.keys()])
        return sorted({m.group(1).split(".")[0] for m in _TEMPLATE_RE.finditer(blob)}
                      | set(self.inject.keys()))


@dataclass
class GraphExecutionResult:
    order: List[str] = field(default_factory=list)
    responses: Dict[str, Optional[HttpResponse]] = field(default_factory=dict)
    captured: Dict[str, str] = field(default_factory=dict)


class DependencyGraphEngine:
    """Parses a response sequence, extracts variables, and injects them forward.

    Given a set of :class:`RequestSpec` nodes, the engine:

    1. topologically orders nodes so producers of a variable run before their
       consumers (a variable is *produced* by a node's :class:`ExtractionRule`
       and *consumed* via ``{{var}}`` templates or explicit ``inject`` targets);
    2. resolves each node's request against the live :class:`SessionStateManager`
       vault (headers, body and path variables);
    3. executes it over the throttled :class:`AsyncHttpClient`;
    4. extracts variables from the response back into the vault for the next
       layer.

    It works equally well over a *pre-recorded* response sequence (offline
    parsing) via :meth:`extract_sequence`.
    """

    def __init__(self, vault: Optional[SessionStateManager] = None,
                 logger: Optional[Logger] = None) -> None:
        self.vault = vault or SessionStateManager()
        self._log = logger or (lambda msg: None)

    # -- ordering ------------------------------------------------------------
    def order(self, specs: Sequence[RequestSpec]) -> List[RequestSpec]:
        producer: Dict[str, int] = {}
        for idx, spec in enumerate(specs):
            for var in spec.produced():
                producer[var] = idx
        indeg = [0] * len(specs)
        adj: Dict[int, List[int]] = {i: [] for i in range(len(specs))}
        for idx, spec in enumerate(specs):
            for var in spec.consumed():
                src = producer.get(var)
                if src is not None and src != idx:
                    adj[src].append(idx)
                    indeg[idx] += 1
        ready = [i for i in range(len(specs)) if indeg[i] == 0]
        out: List[int] = []
        while ready:
            n = ready.pop(0)
            out.append(n)
            for nxt in adj[n]:
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    ready.append(nxt)
        if len(out) != len(specs):  # cycle: preserve declaration order
            out.extend(i for i in range(len(specs)) if i not in out)
        return [specs[i] for i in out]

    # -- request resolution --------------------------------------------------
    def resolve_request(self, base: str, spec: RequestSpec
                        ) -> Tuple[str, Dict[str, str], Optional[str]]:
        """Resolve a spec into a concrete (url, headers, body) using the vault."""
        path = self.vault.resolve(spec.path)
        headers = {k: self.vault.resolve(v) for k, v in spec.headers.items()}
        headers.update(self.vault.cookie_header())
        body = self.vault.resolve(spec.body) if spec.body is not None else None

        # Explicit injections into headers / body / path.
        for var, target in spec.inject.items():
            value = self.vault.get(var, "")
            if target.startswith("header:"):
                headers[target.split(":", 1)[1]] = value or ""
            elif target.startswith("body:"):
                field_name = target.split(":", 1)[1]
                pair = f"{field_name}={value}"
                body = pair if not body else (body + "&" + pair)
            elif target == "path":
                path = path.replace("{{" + var + "}}", value or "")

        url = base.rstrip("/") + (path if path.startswith("/") else "/" + path)
        return url, headers, body

    # -- extraction ----------------------------------------------------------
    def extract_into_vault(self, spec: RequestSpec, resp: HttpResponse) -> Dict[str, str]:
        captured: Dict[str, str] = {}
        self.vault.ingest_response(resp)
        for rule in spec.extract:
            value = rule.apply(resp)
            if value is not None:
                self.vault.put(rule.name, value)
                captured[rule.name] = value
                self._log(f"[depgraph] captured {rule.name}={value[:48]!r} "
                          f"from '{spec.name}'")
        return captured

    def extract_sequence(self, pairs: Sequence[Tuple[RequestSpec, HttpResponse]]
                         ) -> Dict[str, str]:
        """Parse a pre-recorded (spec, response) sequence into the vault."""
        captured: Dict[str, str] = {}
        for spec, resp in pairs:
            captured.update(self.extract_into_vault(spec, resp))
        return captured

    # -- live execution ------------------------------------------------------
    async def execute(self, base: str, specs: Sequence[RequestSpec],
                      client: "AsyncHttpClient") -> GraphExecutionResult:
        """Run the ordered graph live, threading the vault through each node."""
        result = GraphExecutionResult()
        for spec in self.order(specs):
            url, headers, body = self.resolve_request(base, spec)
            self._log(f"[depgraph] -> {spec.name}: {spec.method} {url}")
            resp = await client.request(spec.method, url, headers=headers, data=body)
            result.order.append(spec.name)
            result.responses[spec.name] = resp
            if resp is not None:
                result.captured.update(self.extract_into_vault(spec, resp))
        return result
