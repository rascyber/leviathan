# -*- coding: utf-8 -*-
"""
sternuke.intelligence
=====================

Autonomous, local advisory pipeline.

When the engine or a fuzzer flags an anomaly, this module turns the raw
request/response block (or smart-contract state drift) into three deliverables,
entirely offline:

1. a **deterministic CVSS v3.1** base score + vector string, computed with the
   official formula (:class:`CVSSCalculator`) - the same inputs always yield the
   same score;
2. a **Nuclei-compliant YAML template** (:class:`NucleiTemplateWriter`) for web
   findings, or a structured advisory template for other domains;
3. a **HackerOne-ready Markdown report** (:class:`HackerOneReporter`) with
   Executive Summary, Technical Deep-Dive, Steps to Reproduce, Impact and
   Remediation.

The natural-language prose is drafted by a *local* model
(Ollama/vLLM at ``http://localhost:11434/v1``) when reachable, and by
deterministic templates otherwise, so the pipeline never depends on any external
service.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from .engine import Finding
from .ai_agent import LocalModelClient

Logger = Any


# ===========================================================================
# CVSS v3.1 (deterministic, official formula)
# ===========================================================================
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


@dataclass
class CVSSVector:
    """CVSS v3.1 base metric group."""

    AV: str = "N"   # Attack Vector: N/A/L/P
    AC: str = "L"   # Attack Complexity: L/H
    PR: str = "N"   # Privileges Required: N/L/H
    UI: str = "N"   # User Interaction: N/R
    S: str = "U"    # Scope: U/C
    C: str = "H"    # Confidentiality: N/L/H
    I: str = "H"    # Integrity: N/L/H
    A: str = "H"    # Availability: N/L/H

    def vector_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}"
                f"/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}")


class CVSSCalculator:
    """Computes the CVSS v3.1 base score deterministically."""

    @staticmethod
    def _roundup(value: float) -> float:
        # Official CVSS v3.1 roundup: ceil to one decimal via integer math.
        int_input = round(value * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        return (math.floor(int_input / 10000) + 1) / 10.0

    @classmethod
    def base_score(cls, v: CVSSVector) -> float:
        scope_changed = v.S == "C"
        iss = 1 - ((1 - _CIA[v.C]) * (1 - _CIA[v.I]) * (1 - _CIA[v.A]))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        pr = _PR_CHANGED[v.PR] if scope_changed else _PR_UNCHANGED[v.PR]
        exploitability = 8.22 * _AV[v.AV] * _AC[v.AC] * pr * _UI[v.UI]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return cls._roundup(min(1.08 * (impact + exploitability), 10.0))
        return cls._roundup(min(impact + exploitability, 10.0))

    @staticmethod
    def severity(score: float) -> str:
        if score == 0.0:
            return "None"
        if score < 4.0:
            return "Low"
        if score < 7.0:
            return "Medium"
        if score < 9.0:
            return "High"
        return "Critical"


# ===========================================================================
# Anomaly context (the pipeline's input)
# ===========================================================================
@dataclass
class AnomalyContext:
    """Normalised description of a flagged anomaly to be written up."""

    title: str
    category: str = "web"                 # web | blockchain | binary
    target: str = ""
    location: str = ""                    # URL / contract::fn / binary path
    evidence: str = ""
    request_block: str = ""               # raw HTTP request (web)
    response_block: str = ""              # raw HTTP response (web)
    parameter: str = ""
    payload: str = ""
    state_drift: str = ""                 # contract state before/after (blockchain)
    tags: List[str] = field(default_factory=list)
    cwe: str = ""

    @classmethod
    def from_finding(cls, finding: Finding, *,
                     request_block: str = "", response_block: str = "",
                     state_drift: str = "") -> "AnomalyContext":
        category = "web"
        if "blockchain" in finding.tags:
            category = "blockchain"
        elif "binary" in finding.tags:
            category = "binary"
        return cls(
            title=finding.name, category=category, target=finding.target,
            location=finding.matched_at, evidence=finding.evidence,
            request_block=request_block, response_block=response_block,
            state_drift=state_drift, tags=list(finding.tags),
        )


# ===========================================================================
# Deterministic CVSS mapping from an anomaly
# ===========================================================================
class SeverityMapper:
    """Maps an :class:`AnomalyContext` to a deterministic CVSS vector.

    The mapping is rule-based on the finding's tags/category so identical
    findings always score identically. It is intentionally conservative and can
    be overridden by an explicit vector.
    """

    # (predicate keyword set, CVSS overrides, CWE)
    _RULES: List[Tuple[Tuple[str, ...], Dict[str, str], str]] = [
        (("sql", "error-signature", "injection"),
         {"C": "H", "I": "H", "A": "L", "AC": "L"}, "CWE-89"),
        (("reentrancy", "invariant", "flashloan"),
         {"C": "H", "I": "H", "A": "H", "S": "C"}, "CWE-841"),
        (("delegatecall", "proxy"),
         {"C": "H", "I": "H", "A": "H", "S": "C"}, "CWE-829"),
        (("crash", "segv", "sigsegv", "sigabrt", "fuzzing"),
         {"C": "L", "I": "L", "A": "H", "AV": "L"}, "CWE-787"),
        (("business-logic", "race-condition"),
         {"C": "L", "I": "H", "A": "L", "AC": "H"}, "CWE-362"),
        (("authz", "idor", "authorization"),
         {"C": "H", "I": "H", "A": "N", "PR": "L"}, "CWE-639"),
        (("exposure", "secrets", "disclosure"),
         {"C": "H", "I": "N", "A": "N"}, "CWE-200"),
        (("misconfig", "headers"),
         {"C": "L", "I": "N", "A": "N"}, "CWE-16"),
    ]

    def map(self, ctx: AnomalyContext,
            override: Optional[CVSSVector] = None) -> Tuple[CVSSVector, str]:
        if override is not None:
            return override, ctx.cwe or "CWE-0"
        haystack = " ".join(ctx.tags + [ctx.title, ctx.evidence]).lower()
        vector = CVSSVector()  # default: network, high impact
        cwe = ctx.cwe or "CWE-0"
        for keywords, overrides, rule_cwe in self._RULES:
            if any(k in haystack for k in keywords):
                for field_name, val in overrides.items():
                    setattr(vector, field_name, val)
                cwe = ctx.cwe or rule_cwe
                break
        # Local-only vectors (binary) are not network-reachable by default.
        if ctx.category == "binary" and "AV" not in {}:
            vector.AV = "L"
        return vector, cwe


# ===========================================================================
# Nuclei template writer
# ===========================================================================
class NucleiTemplateWriter:
    """Emits Nuclei-compliant YAML templates for web findings."""

    def build(self, ctx: AnomalyContext, severity: str) -> Dict[str, Any]:
        template_id = self._slug(ctx.title)
        info = {
            "name": ctx.title,
            "author": "sternuke",
            "severity": severity.lower(),
            "description": (ctx.evidence or ctx.title)[:500],
            "tags": ",".join(ctx.tags[:8]) or ctx.category,
        }
        if ctx.category != "web":
            # Non-HTTP domains: emit a structured, valid-YAML advisory template.
            return {
                "id": template_id,
                "info": info,
                "self-contained": True,
                "metadata": {
                    "domain": ctx.category,
                    "location": ctx.location,
                    "evidence": ctx.evidence,
                },
            }
        method, path = self._extract_request(ctx)
        matcher = self._extract_matcher(ctx)
        return {
            "id": template_id,
            "info": info,
            "http": [{
                "method": method,
                "path": [path],
                "matchers-condition": "and",
                "matchers": matcher,
            }],
        }

    def to_yaml(self, template: Dict[str, Any]) -> str:
        if yaml is None:
            raise RuntimeError("PyYAML is required to emit Nuclei templates")
        return yaml.safe_dump(template, sort_keys=False, default_flow_style=False)

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _slug(text: str) -> str:
        s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
        return (s or "sternuke-finding")[:60]

    @staticmethod
    def _extract_request(ctx: AnomalyContext) -> Tuple[str, str]:
        method = "GET"
        path = "{{BaseURL}}/"
        if ctx.request_block:
            first = ctx.request_block.strip().splitlines()[0] if ctx.request_block.strip() else ""
            m = re.match(r"([A-Z]+)\s+(\S+)", first)
            if m:
                method = m.group(1)
                raw_path = m.group(2)
                path = "{{BaseURL}}" + (raw_path if raw_path.startswith("/") else "/" + raw_path)
        elif ctx.location:
            m = re.match(r"https?://[^/]+(/\S*)?", ctx.location)
            path = "{{BaseURL}}" + (m.group(1) if m and m.group(1) else "/")
        return method, path

    @staticmethod
    def _extract_matcher(ctx: AnomalyContext) -> List[Dict[str, Any]]:
        matchers: List[Dict[str, Any]] = []
        # Word matcher from an error signature in the evidence, when present.
        sig = None
        m = re.search(r"error signature: '([^']+)'", ctx.evidence)
        if m:
            sig = m.group(1)
        if sig:
            matchers.append({"type": "word", "part": "body", "words": [sig]})
        else:
            matchers.append({"type": "status", "status": [500]})
        return matchers


# ===========================================================================
# HackerOne Markdown reporter
# ===========================================================================
class HackerOneReporter:
    """Renders a HackerOne-style Markdown advisory."""

    def render(self, ctx: AnomalyContext, vector: CVSSVector, score: float,
               severity: str, cwe: str, narrative: Dict[str, str]) -> str:
        lines: List[str] = []
        lines.append(f"# {ctx.title}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"| --- | --- |")
        lines.append(f"| Severity | **{severity}** ({score:.1f}) |")
        lines.append(f"| CVSS v3.1 | `{vector.vector_string()}` |")
        lines.append(f"| Weakness | {cwe} |")
        lines.append(f"| Asset | {ctx.target or ctx.location} |")
        lines.append(f"| Category | {ctx.category} |")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(narrative.get("summary", ""))
        lines.append("")
        lines.append("## Technical Deep-Dive")
        lines.append(narrative.get("technical", ""))
        if ctx.request_block:
            lines.append("")
            lines.append("**Request**")
            lines.append("```http")
            lines.append(ctx.request_block.strip())
            lines.append("```")
        if ctx.response_block:
            lines.append("")
            lines.append("**Response (excerpt)**")
            lines.append("```http")
            lines.append(ctx.response_block.strip()[:1200])
            lines.append("```")
        if ctx.state_drift:
            lines.append("")
            lines.append("**Contract state drift**")
            lines.append("```")
            lines.append(ctx.state_drift.strip()[:1200])
            lines.append("```")
        lines.append("")
        lines.append("## Steps to Reproduce")
        lines.append(narrative.get("steps", ""))
        lines.append("")
        lines.append("## Impact")
        lines.append(narrative.get("impact", ""))
        lines.append("")
        lines.append("## Remediation")
        lines.append(narrative.get("remediation", ""))
        lines.append("")
        lines.append("---")
        lines.append(f"_Report generated locally by sternuke intelligence pipeline "
                     f"on {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}. "
                     f"For authorised assessment use only._")
        return "\n".join(lines)


# ===========================================================================
# Orchestrator
# ===========================================================================
@dataclass
class Advisory:
    """The full set of artefacts produced for one anomaly."""

    context: AnomalyContext
    cvss_vector: CVSSVector
    cvss_score: float
    severity: str
    cwe: str
    nuclei_template: Dict[str, Any]
    markdown_report: str
    files: Dict[str, str] = field(default_factory=dict)


class IntelligenceEngine:
    """Turns anomalies into scored advisories, Nuclei templates and reports."""

    def __init__(self, model_client: Optional[LocalModelClient] = None,
                 logger: Optional[Any] = None):
        self.model = model_client
        self._log = logger or (lambda msg: None)
        self.calc = CVSSCalculator()
        self.mapper = SeverityMapper()
        self.nuclei = NucleiTemplateWriter()
        self.reporter = HackerOneReporter()

    async def analyze(self, ctx: AnomalyContext, *,
                      cvss_override: Optional[CVSSVector] = None) -> Advisory:
        vector, cwe = self.mapper.map(ctx, override=cvss_override)
        score = self.calc.base_score(vector)
        severity = self.calc.severity(score)
        narrative = await self._narrative(ctx, vector, score, severity, cwe)
        template = self.nuclei.build(ctx, severity)
        markdown = self.reporter.render(ctx, vector, score, severity, cwe, narrative)
        self._log(f"[intel] {severity} ({score:.1f}) :: {ctx.title}")
        return Advisory(ctx, vector, score, severity, cwe, template, markdown)

    async def analyze_finding(self, finding: Finding, **kwargs: Any) -> Advisory:
        ctx = AnomalyContext.from_finding(finding, **{
            k: v for k, v in kwargs.items()
            if k in ("request_block", "response_block", "state_drift")})
        return await self.analyze(ctx)

    def write_advisory(self, advisory: Advisory, output_dir: str) -> Dict[str, str]:
        """Persist the Markdown report and Nuclei YAML, grouped by severity."""
        sev_dir = os.path.join(output_dir, "advisories", advisory.severity.lower())
        os.makedirs(sev_dir, exist_ok=True)
        slug = NucleiTemplateWriter._slug(advisory.context.title)
        md_path = os.path.join(sev_dir, f"{slug}.md")
        yaml_path = os.path.join(sev_dir, f"{slug}.yaml")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(advisory.markdown_report)
        try:
            with open(yaml_path, "w", encoding="utf-8") as fh:
                fh.write(self.nuclei.to_yaml(advisory.nuclei_template))
        except RuntimeError as exc:
            self._log(f"[intel] YAML skipped: {exc}")
            yaml_path = ""
        advisory.files = {"markdown": md_path, "nuclei": yaml_path}
        self._log(f"[intel] wrote advisory -> {md_path}")
        return advisory.files

    # -- narrative generation (local model + deterministic fallback) ---------
    async def _narrative(self, ctx: AnomalyContext, vector: CVSSVector,
                         score: float, severity: str, cwe: str) -> Dict[str, str]:
        if self.model is not None:
            drafted = await self._model_narrative(ctx, vector, score, severity, cwe)
            if drafted:
                return drafted
        return self._fallback_narrative(ctx, vector, score, severity, cwe)

    async def _model_narrative(self, ctx: AnomalyContext, vector: CVSSVector,
                               score: float, severity: str, cwe: str
                               ) -> Optional[Dict[str, str]]:
        system = (
            "You are a defensive security analyst writing an authorised-assessment "
            "vulnerability advisory. Return ONLY JSON with keys: summary, technical, "
            "steps, impact, remediation. Be precise and non-destructive; do not "
            "include working exploit code, only reproduction steps."
        )
        user = json.dumps({
            "title": ctx.title, "category": ctx.category, "severity": severity,
            "cvss": vector.vector_string(), "cwe": cwe, "asset": ctx.target,
            "location": ctx.location, "evidence": ctx.evidence,
            "request": ctx.request_block[:1500], "response": ctx.response_block[:1500],
            "state_drift": ctx.state_drift[:1500],
        })
        raw = await self.model.chat(system, user)
        if not raw:
            return None
        try:
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            data = json.loads(m.group(0)) if m else {}
        except (json.JSONDecodeError, AttributeError):
            return None
        keys = ("summary", "technical", "steps", "impact", "remediation")
        if not any(k in data for k in keys):
            return None
        return {k: str(data.get(k, "")).strip() for k in keys}

    def _fallback_narrative(self, ctx: AnomalyContext, vector: CVSSVector,
                            score: float, severity: str, cwe: str) -> Dict[str, str]:
        loc = ctx.location or ctx.target
        steps: List[str]
        if ctx.category == "web":
            steps = [
                f"1. Send a request to `{loc}`"
                + (f" with parameter `{ctx.parameter}`" if ctx.parameter else "") + ".",
                f"2. Supply the test input `{ctx.payload or '<mutated value>'}`.",
                "3. Observe the anomalous response captured below (the evidence "
                "shows the input reaching a sensitive sink or an unhandled path).",
            ]
        elif ctx.category == "blockchain":
            steps = [
                f"1. Deploy the contract to a local test node and target `{loc}`.",
                "2. Execute the call sequence recorded during fuzzing.",
                "3. Re-check the invariant/property; it no longer holds "
                "(see state drift below).",
            ]
        else:
            steps = [
                f"1. Run the target `{loc}` under a debugger or sanitizer.",
                "2. Provide the saved crashing input from the fuzzing corpus.",
                "3. Observe termination via the reported signal.",
            ]
        return {
            "summary": (f"A {severity.lower()}-severity {ctx.category} issue "
                        f"(\"{ctx.title}\") was identified on `{ctx.target or loc}`. "
                        f"CVSS v3.1 base score {score:.1f} ({vector.vector_string()})."),
            "technical": (f"{ctx.title}. {ctx.evidence} "
                          f"The weakness is classified as {cwe}. This was surfaced "
                          f"by the sternuke assessment engine during authorised "
                          f"testing of the asset."),
            "steps": "\n".join(steps),
            "impact": self._impact_text(vector, severity, ctx.category),
            "remediation": self._remediation_text(ctx),
        }

    @staticmethod
    def _impact_text(vector: CVSSVector, severity: str, category: str) -> str:
        parts = []
        if vector.C == "H":
            parts.append("disclosure of confidential data")
        if vector.I == "H":
            parts.append("unauthorised modification of data or state")
        if vector.A == "H":
            parts.append("loss of availability")
        impact = ", ".join(parts) or "a limited security impact"
        scope = ("and the impact crosses a security boundary (scope changed)"
                 if vector.S == "C" else "within the affected component")
        return (f"Successful exploitation could lead to {impact} {scope}. "
                f"Rated {severity} under CVSS v3.1.")

    @staticmethod
    def _remediation_text(ctx: AnomalyContext) -> str:
        tags = set(ctx.tags)
        if "reentrancy" in tags or "invariant" in tags:
            return ("Apply the checks-effects-interactions pattern, add a "
                    "reentrancy guard, and add the missing invariant precondition.")
        if "error-signature" in tags or "sql" in tags:
            return ("Use parameterised queries/ORM bindings, validate and "
                    "canonicalise input, and return generic error pages.")
        if "crash" in tags or "fuzzing" in tags:
            return ("Add bounds/type validation at the fault site and rebuild with "
                    "sanitizers in CI to catch memory-safety regressions.")
        if "authz" in tags or "idor" in tags:
            return ("Enforce object- and function-level authorization server-side "
                    "for every request, keyed to the authenticated principal.")
        return ("Validate untrusted input, apply least privilege, and add a "
                "regression test that reproduces this finding.")
