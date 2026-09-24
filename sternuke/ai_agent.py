# -*- coding: utf-8 -*-
"""
sternuke.ai_agent
=================

The "brain" of the sternuke framework.

This module is responsible for three things:

1. **Static structural analysis** of blockchain source files (Solidity / Rust).
   Before any model ever sees the code, sternuke builds a deterministic
   *architectural blueprint* - contracts, functions, visibility, access
   controls, state variables - using local parsing only.

2. **Context construction** for web endpoints (observed technologies, headers,
   forms and reflected parameters), again produced locally.

3. **Local model orchestration.** The :class:`AIAgent` talks *only* to a local
   inference server (Ollama / vLLM) exposed on the standard OpenAI-compatible
   endpoint (``http://localhost:11434/v1``). It feeds the blueprint / context to
   the model, asks it to form targeted hypotheses, and then persists the
   synthesised detection rules as local JSON/YAML files for
   :mod:`sternuke.engine` to execute.

No third-party SaaS, commercial API or paid feed is contacted. If the local
model is unavailable the agent degrades gracefully to a set of built-in
heuristic hypotheses so the framework remains useful offline.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional

try:
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


# ============================================================================
# Blockchain static analysis
# ============================================================================
@dataclass
class FunctionInfo:
    name: str
    visibility: str = "internal"          # public / external / internal / private
    mutability: str = ""                  # view / pure / payable
    modifiers: List[str] = field(default_factory=list)
    returns: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StateVariable:
    name: str
    type: str
    visibility: str = "internal"
    constant: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ContractBlueprint:
    """A structural model of a single contract / module."""

    name: str
    kind: str                              # contract / interface / library / rust-module
    language: str
    path: str
    inherits: List[str] = field(default_factory=list)
    functions: List[FunctionInfo] = field(default_factory=list)
    state_variables: List[StateVariable] = field(default_factory=list)
    modifiers_defined: List[str] = field(default_factory=list)
    access_controls: List[str] = field(default_factory=list)
    uses_delegatecall: bool = False
    uses_selfdestruct: bool = False
    uses_low_level_call: bool = False
    handles_ether: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["functions"] = [f.to_dict() for f in self.functions]
        d["state_variables"] = [v.to_dict() for v in self.state_variables]
        return d


class SolidityAnalyzer:
    """Regex-based structural extractor for Solidity sources.

    This is intentionally a *lightweight* parser: it recovers enough structure
    (contracts, functions, visibility, modifiers, risky primitives) to give the
    model a faithful blueprint, without pulling in a full Solidity toolchain.
    """

    _CONTRACT = re.compile(
        r"\b(?P<kind>contract|interface|library)\s+(?P<name>[A-Za-z_]\w*)"
        r"(?:\s+is\s+(?P<inherits>[^{]+))?\s*{",
        re.MULTILINE,
    )
    _FUNCTION = re.compile(
        r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)\s*(?P<attrs>[^{;]*)",
        re.MULTILINE,
    )
    _MODIFIER_DEF = re.compile(r"\bmodifier\s+(?P<name>[A-Za-z_]\w*)", re.MULTILINE)
    _STATE_VAR = re.compile(
        r"^\s*(?P<type>address|uint\d*|int\d*|bool|bytes\d*|string|mapping\s*\([^)]*\))"
        r"\s+(?P<mods>(?:public|private|internal|constant|immutable)\s+)*"
        r"(?P<name>[A-Za-z_]\w*)\s*[;=]",
        re.MULTILINE,
    )
    _VISIBILITY = ("external", "public", "internal", "private")
    _MUTABILITY = ("view", "pure", "payable")
    _ACCESS_HINTS = ("onlyOwner", "onlyAdmin", "onlyRole", "require(msg.sender",
                     "Ownable", "AccessControl", "hasRole")

    def analyze(self, path: str, code: str) -> List[ContractBlueprint]:
        blueprints: List[ContractBlueprint] = []
        matches = list(self._CONTRACT.finditer(code))
        for i, m in enumerate(matches):
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(code)
            body = code[start:end]
            bp = ContractBlueprint(
                name=m.group("name"),
                kind=m.group("kind"),
                language="solidity",
                path=path,
                inherits=[s.strip() for s in (m.group("inherits") or "").split(",") if s.strip()],
            )
            self._extract_functions(body, bp)
            self._extract_state(body, bp)
            bp.modifiers_defined = [mm.group("name") for mm in self._MODIFIER_DEF.finditer(body)]
            self._flag_risky_primitives(body, bp)
            blueprints.append(bp)
        return blueprints

    def _extract_functions(self, body: str, bp: ContractBlueprint) -> None:
        for fm in self._FUNCTION.finditer(body):
            attrs = fm.group("attrs") or ""
            visibility = next((v for v in self._VISIBILITY if re.search(rf"\b{v}\b", attrs)),
                              "public")
            mutability = next((mu for mu in self._MUTABILITY if re.search(rf"\b{mu}\b", attrs)), "")
            # Drop the `returns (...)` clause so declared return types are not
            # mistaken for modifiers.
            attrs_no_returns = re.sub(r"returns\s*\([^)]*\)", " ", attrs)
            modifiers = [tok for tok in re.findall(r"\b[A-Za-z_]\w*\b", attrs_no_returns)
                         if tok not in self._VISIBILITY and tok not in self._MUTABILITY
                         and tok not in ("returns",)]
            fn = FunctionInfo(fm.group("name"), visibility, mutability, modifiers)
            bp.functions.append(fn)
            if any(a in attrs for a in self._ACCESS_HINTS) or any(
                mod for mod in modifiers if mod.lower().startswith("only")
            ):
                bp.access_controls.append(fm.group("name"))
            if "payable" in attrs:
                bp.handles_ether = True

    def _extract_state(self, body: str, bp: ContractBlueprint) -> None:
        for sm in self._STATE_VAR.finditer(body):
            mods = sm.group("mods") or ""
            visibility = next((v for v in self._VISIBILITY if v in mods), "internal")
            bp.state_variables.append(StateVariable(
                name=sm.group("name"),
                type=sm.group("type"),
                visibility=visibility,
                constant="constant" in mods,
            ))

    def _flag_risky_primitives(self, body: str, bp: ContractBlueprint) -> None:
        bp.uses_delegatecall = "delegatecall" in body
        bp.uses_selfdestruct = "selfdestruct" in body or "suicide(" in body
        bp.uses_low_level_call = bool(re.search(r"\.call\s*[{(]", body))
        if any(h in body for h in ("msg.value", "address(this).balance", "transfer(", "send(")):
            bp.handles_ether = True
        for hint in self._ACCESS_HINTS:
            if hint in body and hint not in bp.access_controls:
                bp.access_controls.append(hint)


class RustAnalyzer:
    """Structural extractor for Rust sources (Solana / Substrate style).

    Recovers modules, ``pub fn`` visibility, structs and a handful of primitives
    relevant to on-chain code (signer checks, unsafe blocks, arithmetic).
    """

    _FN = re.compile(r"\b(?P<vis>pub(?:\([^)]*\))?\s+)?fn\s+(?P<name>[A-Za-z_]\w*)", re.MULTILINE)
    _STRUCT = re.compile(r"\b(?P<vis>pub\s+)?struct\s+(?P<name>[A-Za-z_]\w*)", re.MULTILINE)
    _MODULE = re.compile(r"\bmod\s+(?P<name>[A-Za-z_]\w*)", re.MULTILINE)

    def analyze(self, path: str, code: str) -> List[ContractBlueprint]:
        module_name = os.path.splitext(os.path.basename(path))[0]
        bp = ContractBlueprint(
            name=module_name, kind="rust-module", language="rust", path=path,
        )
        for fm in self._FN.finditer(code):
            visibility = "public" if fm.group("vis") else "private"
            bp.functions.append(FunctionInfo(fm.group("name"), visibility))
        for sm in self._STRUCT.finditer(code):
            visibility = "public" if sm.group("vis") else "private"
            bp.state_variables.append(StateVariable(sm.group("name"), "struct", visibility))
        # Access-control / risk heuristics relevant to on-chain Rust.
        if "is_signer" in code or "Signer" in code:
            bp.access_controls.append("signer-check")
        if "require!" in code or "assert!" in code or "ensure!" in code:
            bp.access_controls.append("assertion-guard")
        bp.uses_low_level_call = "invoke(" in code or "invoke_signed(" in code
        bp.handles_ether = "lamports" in code or "transfer" in code
        if "unsafe" in code:
            bp.modifiers_defined.append("unsafe-block")
        return [bp]


# ============================================================================
# Web context construction
# ============================================================================
class WebContextBuilder:
    """Builds a compact, model-ready context object from an endpoint response."""

    _FORM = re.compile(r"<form[^>]*>", re.IGNORECASE)
    _INPUT = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
    _TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "via", "x-generator")

    def build(self, url: str, status: int, headers: Dict[str, str], body: str) -> Dict[str, Any]:
        tech = {h: headers[h] for h in headers if h.lower() in self._TECH_HEADERS}
        forms = len(self._FORM.findall(body or ""))
        params = sorted(set(self._INPUT.findall(body or "")))
        return {
            "url": url,
            "status": status,
            "technologies": tech,
            "form_count": forms,
            "input_parameters": params[:40],
            "title": self._title(body or ""),
        }

    @staticmethod
    def _title(body: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return (m.group(1).strip()[:120] if m else "")


# ============================================================================
# Local model client (Ollama / vLLM, OpenAI-compatible)
# ============================================================================
@dataclass
class ModelConfig:
    base_url: str = "http://localhost:11434/v1"
    model: str = "deepseek-coder"
    temperature: float = 0.2
    max_tokens: int = 2048
    timeout: float = 120.0
    api_key: str = "ollama"   # local servers ignore this; kept for OpenAI-compat


class LocalModelClient:
    """Async client for a local OpenAI-compatible inference server."""

    def __init__(self, config: ModelConfig, logger: Optional[Callable[[str], None]] = None):
        self.config = config
        self._log = logger or (lambda msg: None)

    async def chat(self, system: str, user: str) -> Optional[str]:
        """Send a chat completion request. Returns the text, or ``None`` on error."""
        if aiohttp is None:
            self._log("[ai] aiohttp not installed; cannot reach local model")
            return None
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"Authorization": f"Bearer {self.config.api_key}",
                   "Content-Type": "application/json"}
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=payload, headers=headers) as resp:
                    if resp.status != 200:
                        self._log(f"[ai] local model returned HTTP {resp.status}")
                        return None
                    data = await resp.json()
                    return data["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001 - network/parse errors degrade gracefully
            self._log(f"[ai] local model unreachable ({exc}); using offline heuristics")
            return None


# ============================================================================
# AI orchestrator
# ============================================================================
class AIAgent:
    """Autonomous orchestrator: context -> hypotheses -> local rule files.

    The agent takes a blueprint (blockchain) or endpoint context (web), asks the
    local model to synthesise detection rules, validates the output, and writes
    the rules to disk in the schema understood by :mod:`sternuke.engine`.
    """

    SYSTEM_PROMPT = (
        "You are a defensive security assistant that writes vulnerability "
        "DETECTION rules for an authorised assessment tool. You never write "
        "exploit payloads that cause damage. You output only valid JSON: an "
        "object with a top-level 'rules' array. Each rule has: id, "
        "info{name,severity,description,remediation}, and for web rules a "
        "'requests' array of {method,path,matchers[{type,words|regex|status}]}. "
        "For blockchain findings, requests may be omitted and the finding is "
        "advisory. Severity is one of info/low/medium/high/critical."
    )

    def __init__(self, model_client: LocalModelClient,
                 logger: Optional[Callable[[str], None]] = None):
        self.model = model_client
        self._log = logger or (lambda msg: None)
        self.solidity = SolidityAnalyzer()
        self.rust = RustAnalyzer()
        self.web_context = WebContextBuilder()

    # -- blockchain blueprint -------------------------------------------------
    def build_blueprints(self, source_files) -> List[ContractBlueprint]:
        """Produce structural blueprints from crawled :class:`SourceFile` objects."""
        blueprints: List[ContractBlueprint] = []
        for sf in source_files:
            try:
                if sf.language == "solidity":
                    blueprints.extend(self.solidity.analyze(sf.path, sf.content))
                elif sf.language == "rust":
                    blueprints.extend(self.rust.analyze(sf.path, sf.content))
            except Exception as exc:  # noqa: BLE001
                self._log(f"[ai] failed to model {sf.path}: {exc}")
        self._log(f"[ai] built {len(blueprints)} contract blueprint(s)")
        return blueprints

    # -- rule synthesis -------------------------------------------------------
    async def synthesize_from_blueprints(
        self, blueprints: List[ContractBlueprint], out_dir: str, fmt: str = "yaml"
    ) -> str:
        summary = self._summarise_blueprints(blueprints)
        user = (
            "Given the following smart-contract architectural blueprint, propose "
            "targeted, non-destructive audit findings/hypotheses and return them "
            "as detection rules in the required JSON schema. Focus on access "
            "control gaps, unchecked external calls, reentrancy exposure, integer "
            "handling and privileged functions.\n\nBLUEPRINT:\n" + summary
        )
        rules = await self._request_rules(user)
        if not rules:
            rules = self._offline_blueprint_rules(blueprints)
        return self._write_rules(rules, out_dir, fmt, prefix="blockchain")

    async def synthesize_from_web_context(
        self, contexts: List[Dict[str, Any]], out_dir: str, fmt: str = "yaml"
    ) -> str:
        user = (
            "Given the following observed web endpoints, propose non-destructive "
            "detection rules (misconfiguration, information disclosure, exposed "
            "files, security-header gaps) in the required JSON schema.\n\n"
            "ENDPOINTS:\n" + json.dumps(contexts, indent=2)[:6000]
        )
        rules = await self._request_rules(user)
        if not rules:
            rules = self._offline_web_rules()
        return self._write_rules(rules, out_dir, fmt, prefix="web")

    async def _request_rules(self, user_prompt: str) -> List[Dict[str, Any]]:
        raw = await self.model.chat(self.SYSTEM_PROMPT, user_prompt)
        if not raw:
            return []
        parsed = self._extract_json(raw)
        rules = parsed.get("rules", []) if isinstance(parsed, dict) else []
        valid = [r for r in rules if self._validate_rule(r)]
        self._log(f"[ai] model synthesised {len(valid)} valid rule(s)")
        return valid

    # -- helpers --------------------------------------------------------------
    @staticmethod
    def _summarise_blueprints(blueprints: List[ContractBlueprint]) -> str:
        lines: List[str] = []
        for bp in blueprints:
            lines.append(f"# {bp.kind} {bp.name} ({bp.language}) [{os.path.basename(bp.path)}]")
            if bp.inherits:
                lines.append(f"  inherits: {', '.join(bp.inherits)}")
            for fn in bp.functions:
                mods = f" mods={fn.modifiers}" if fn.modifiers else ""
                lines.append(f"  fn {fn.name} [{fn.visibility} {fn.mutability}]{mods}")
            flags = [k for k, v in {
                "delegatecall": bp.uses_delegatecall,
                "selfdestruct": bp.uses_selfdestruct,
                "low_level_call": bp.uses_low_level_call,
                "handles_ether": bp.handles_ether,
            }.items() if v]
            if flags:
                lines.append(f"  risk_primitives: {', '.join(flags)}")
            if bp.access_controls:
                lines.append(f"  access_controls: {', '.join(sorted(set(bp.access_controls)))}")
        return "\n".join(lines)[:6000]

    @staticmethod
    def _extract_json(text: str) -> Dict[str, Any]:
        # Tolerate models that wrap JSON in prose or ```json fences.
        fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        candidate = fence.group(1) if fence else text
        if not fence:
            brace = candidate.find("{")
            if brace != -1:
                candidate = candidate[brace:]
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            return {}

    @staticmethod
    def _validate_rule(rule: Any) -> bool:
        if not isinstance(rule, dict):
            return False
        if not (rule.get("id") or rule.get("info", {}).get("name")):
            return False
        return True

    def _write_rules(self, rules: List[Dict[str, Any]], out_dir: str,
                     fmt: str, prefix: str) -> str:
        os.makedirs(out_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        ext = "yaml" if fmt == "yaml" else "json"
        path = os.path.join(out_dir, f"{prefix}-synth-{ts}.{ext}")
        payload = {"generated_by": "sternuke.ai_agent",
                   "generated_at": ts, "rules": rules}
        with open(path, "w", encoding="utf-8") as fh:
            if fmt == "yaml":
                if yaml is None:
                    raise RuntimeError("PyYAML required to write YAML rules")
                yaml.safe_dump_all(rules, fh, sort_keys=False)
            else:
                json.dump(payload, fh, indent=2)
        self._log(f"[ai] wrote {len(rules)} rule(s) -> {path}")
        return path

    # -- offline fallbacks ----------------------------------------------------
    def _offline_blueprint_rules(self, blueprints: List[ContractBlueprint]) -> List[Dict[str, Any]]:
        """Deterministic heuristic findings when the local model is unavailable."""
        rules: List[Dict[str, Any]] = []
        for bp in blueprints:
            unguarded = [fn.name for fn in bp.functions
                         if fn.visibility in ("public", "external")
                         and not fn.modifiers and fn.name not in bp.access_controls
                         and fn.mutability not in ("view", "pure")]
            if unguarded and (bp.handles_ether or bp.uses_delegatecall or bp.uses_selfdestruct):
                rules.append({
                    "id": f"advisory-privileged-{bp.name.lower()}",
                    "info": {
                        "name": f"State-changing functions without access control in {bp.name}",
                        "severity": "high" if bp.handles_ether else "medium",
                        "description": (
                            f"Functions {', '.join(unguarded[:6])} are externally callable, "
                            f"mutate state and lack visible access-control modifiers while the "
                            f"contract uses sensitive primitives."),
                        "remediation": "Add owner/role checks (e.g. onlyOwner / AccessControl) "
                                       "to privileged state-changing functions.",
                        "tags": ["blockchain", "access-control", bp.language],
                    },
                })
            if bp.uses_low_level_call:
                rules.append({
                    "id": f"advisory-lowlevel-call-{bp.name.lower()}",
                    "info": {
                        "name": f"Unchecked low-level call in {bp.name}",
                        "severity": "medium",
                        "description": "Low-level .call detected; verify return value handling "
                                       "and reentrancy protections.",
                        "remediation": "Check call success and follow checks-effects-interactions.",
                        "tags": ["blockchain", "reentrancy", bp.language],
                    },
                })
        self._log(f"[ai] offline heuristics produced {len(rules)} advisory rule(s)")
        return rules

    def _offline_web_rules(self) -> List[Dict[str, Any]]:
        """A small built-in web ruleset used when the model is offline."""
        return [
            {
                "id": "missing-security-headers",
                "info": {"name": "Missing security headers", "severity": "low",
                         "description": "Response lacks common hardening headers.",
                         "remediation": "Add Content-Security-Policy, X-Frame-Options, "
                                        "X-Content-Type-Options and Strict-Transport-Security.",
                         "tags": ["web", "misconfig"]},
                "requests": [{"method": "GET", "path": ["/"],
                              "matchers": [{"type": "regex", "part": "header",
                                            "regex": ["(?i)content-security-policy"],
                                            "negative": True}]}],
            },
            {
                "id": "exposed-dotenv",
                "info": {"name": "Exposed .env file", "severity": "high",
                         "description": "A .env environment file is publicly readable.",
                         "remediation": "Block access to dotfiles at the web server.",
                         "tags": ["web", "exposure"]},
                "requests": [{"method": "GET", "path": ["/.env"],
                              "matchers": [{"type": "regex",
                                            "regex": [r"(?i)(APP_KEY|DB_PASSWORD|SECRET)="]}]}],
            },
        ]
