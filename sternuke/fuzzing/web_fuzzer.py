# -*- coding: utf-8 -*-
"""
sternuke.fuzzing.web_fuzzer
===========================

Automated payload mutation for web / API parameters.

The web fuzzer mutates the values of a baseline request's parameters (query
string or form/JSON body) and looks for *anomalies* that indicate a weakness:
server errors (5xx), error-signature reflections (stack traces, SQL/parse
errors), and large response-size deltas versus the baseline. It composes the
:class:`~sternuke.fuzzing.mutator.ByteMutator` with a set of structural /
encoding / type-confusion mutations tuned for web inputs.

Everything runs through the engine's :class:`~sternuke.engine.AsyncHttpClient`,
so the active :class:`~sternuke.engine.ScanPolicy` throttles (concurrency, rate,
request ceiling) apply unchanged. Non-local hosts are refused unless the
operator explicitly accepts responsibility via ``allow_remote``.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..engine import AsyncHttpClient, Finding, HttpResponse, ScanPolicy
from .guards import assert_web_scope
from .mutator import ByteMutator

Logger = Callable[[str], None]

# Error signatures that, when reflected, suggest the input reached a sink.
_ERROR_SIGNATURES = (
    "SQL syntax", "SQLSTATE", "unclosed quotation", "ORA-0", "psql:",
    "Traceback (most recent call last)", "Warning: ", "Fatal error:",
    "java.lang.", "System.Data.SqlClient", "MongoError", "unexpected token",
    "stack trace", "DeserializationError",
)


@dataclass
class WebFuzzBudget:
    payloads_per_param: int = 40
    max_stack: int = 3
    size_delta_ratio: float = 4.0     # response this many x larger than baseline


@dataclass
class WebFuzzReport:
    requests: int = 0
    findings: List[Finding] = field(default_factory=list)


class PayloadMutator:
    """Structural / encoding / type-confusion mutations for a string value."""

    # Boundary and type-confusion seeds (benign markers, not weaponised payloads).
    STRUCTURAL = ["", " ", "0", "-1", "2147483648", "9" * 40,
                  "true", "false", "null", "[]", "{}", "[0]", "{\"$ne\":null}",
                  "%00", "../", "' ", "\" ", "` ", ";", "|", "\n"]

    def __init__(self, seed: int = 0):
        self.rng = random.Random(seed)
        self.byte = ByteMutator(seed=seed)

    def variants(self, value: str, count: int, *, max_stack: int = 3) -> List[str]:
        out: List[str] = []
        # 1) structural boundary/type-confusion values.
        out.extend(self.STRUCTURAL)
        # 2) append/prepend boundary tokens to the original value.
        for token in ("'", "\"", "<x>", "${7*7}", "{{7*7}}", "\x00"):
            out.append(value + token)
        # 3) byte-level havoc over the original value's bytes.
        raw = value.encode("utf-8", "replace") or b"a"
        for mutated in self.byte.batch(raw, max(0, count - len(out)), max_stack=max_stack):
            out.append(mutated.decode("latin-1"))
        # De-duplicate, cap.
        seen, uniq = set(), []
        for v in out:
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        return uniq[:count]


class WebFuzzer:
    """Mutates request parameters and flags anomalous responses."""

    def __init__(self, policy: ScanPolicy, *, budget: Optional[WebFuzzBudget] = None,
                 seed: int = 0, allow_remote: bool = False,
                 logger: Optional[Logger] = None):
        self.policy = policy
        self.budget = budget or WebFuzzBudget()
        self.mutator = PayloadMutator(seed=seed)
        self.allow_remote = allow_remote
        self._log = logger or (lambda msg: None)

    # -- request assembly ----------------------------------------------------
    @staticmethod
    def _baseline_params(url: str, body: Optional[str]) -> Dict[str, str]:
        params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        if body:
            params.update(dict(parse_qsl(body, keep_blank_values=True)))
        return params

    @staticmethod
    def _rebuild(url: str, body: Optional[str], key: str, value: str):
        parsed = urlparse(url)
        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if key in q:
            q[key] = value
            new_url = urlunparse(parsed._replace(query=urlencode(q)))
            return new_url, body
        if body is not None:
            b = dict(parse_qsl(body, keep_blank_values=True))
            b[key] = value
            return url, urlencode(b)
        # No existing slot: add as a query parameter.
        q[key] = value
        return urlunparse(parsed._replace(query=urlencode(q))), body

    # -- anomaly detection ---------------------------------------------------
    def _anomaly(self, resp: Optional[HttpResponse], baseline: HttpResponse,
                 param: str, value: str) -> Optional[Finding]:
        if resp is None:
            return None
        sig = next((s for s in _ERROR_SIGNATURES if s in resp.body), None)
        server_error = 500 <= resp.status < 600
        size_blow = (len(baseline.body) > 0
                     and len(resp.body) > len(baseline.body) * self.budget.size_delta_ratio)
        if not (sig or server_error or size_blow):
            return None
        if sig:
            kind, sev, ev = "error-signature", "high", f"reflected error signature: {sig!r}"
        elif server_error:
            kind, sev, ev = "server-error", "medium", f"HTTP {resp.status} on mutated input"
        else:
            kind, sev, ev = "response-anomaly", "low", (
                f"response size {len(resp.body)} vs baseline {len(baseline.body)}")
        return Finding(
            rule_id=f"webfuzz-{kind}-{param}",
            name=f"Fuzzing anomaly on parameter '{param}' ({kind})",
            severity=sev,
            target=resp.url,
            matched_at=resp.url,
            evidence=f"{ev}; input={value[:60]!r}",
            description="A mutated parameter value produced an anomalous response, "
                        "indicating the input reaches a sensitive sink or an "
                        "unhandled error path. Verify manually before reporting.",
            remediation="Validate and canonicalise the parameter; ensure errors are "
                        "handled without leaking diagnostics.",
            tags=["web", "fuzzing", kind],
        )

    # -- campaign ------------------------------------------------------------
    async def fuzz(self, url: str, *, method: str = "GET", body: Optional[str] = None,
                   headers: Optional[Dict[str, str]] = None) -> WebFuzzReport:
        assert_web_scope(url, allow_remote=self.allow_remote)
        headers = dict(headers or {})
        report = WebFuzzReport()
        params = self._baseline_params(url, body)
        if not params:
            self._log("[webfuzz] no parameters to mutate on target")
            return report

        async with AsyncHttpClient(self.policy, self._log) as client:
            baseline = await client.request(method, url, headers=headers, data=body)
            report.requests += 1
            if baseline is None:
                self._log("[webfuzz] baseline request failed; aborting")
                return report

            seen_rules: set = set()
            for key, value in params.items():
                for variant in self.mutator.variants(
                        value, self.budget.payloads_per_param, max_stack=self.budget.max_stack):
                    m_url, m_body = self._rebuild(url, body, key, variant)
                    resp = await client.request(method, m_url, headers=headers, data=m_body)
                    report.requests += 1
                    finding = self._anomaly(resp, baseline, key, variant)
                    if finding and finding.rule_id not in seen_rules:
                        seen_rules.add(finding.rule_id)
                        report.findings.append(finding)
                        self._log(f"[webfuzz] {finding.severity.upper()} :: {finding.name}")

        self._log(f"[webfuzz] done: {report.requests} request(s), "
                  f"{len(report.findings)} finding(s)")
        return report
