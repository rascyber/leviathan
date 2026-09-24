# -*- coding: utf-8 -*-
"""
sternuke.engine
===============

The "muscle" of the sternuke framework.

This module contains three cooperating pieces:

* :class:`ScanPolicy`  - the safety/throttling contract every scan runs under.
* :class:`AsyncHttpClient` - a thin, rate-limited wrapper around ``aiohttp`` that
  performs non-blocking HTTP requests while respecting the active policy.
* :class:`RuleEngine` / :class:`WebScanner` - the rule execution parser and the
  asynchronous request manager that fuzzes parameters, injects payloads and
  evaluates *local* signatures (regex / word / status matchers).
* :class:`RepoCrawler` - a filesystem crawler that locates blockchain source
  files (Solidity ``.sol`` and Rust ``.rs``) for the AI agent to model.

Design goals
------------
The engine is intentionally conservative. It is an *assessment* tool: it is
built to identify weaknesses on systems the operator is authorised to test, not
to overwhelm them. Concurrency, request rate and per-host fan-out are all capped
by :class:`ScanPolicy`, and the scanner never expands its own target list -
it only ever touches hosts the caller explicitly provides.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

try:
    import aiohttp
except ImportError:  # pragma: no cover - dependency is declared in requirements
    aiohttp = None  # Allows the module to import for offline/static use (repo mode).

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


# ----------------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------------
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    """A single vulnerability / weakness observation produced by the engine."""

    rule_id: str
    name: str
    severity: str
    target: str
    matched_at: str
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"[{self.severity.upper():8}] {self.name} -> {self.matched_at}"


@dataclass
class ScanPolicy:
    """Safety and throttling contract for a scan.

    Every knob here exists to keep sternuke a well-behaved assessment tool.
    The defaults are deliberately gentle; an operator running against their own
    lab can raise them, but the scanner will never silently exceed them.
    """

    max_concurrency: int = 20          # simultaneous in-flight requests, globally
    requests_per_second: float = 25.0  # global token-bucket rate limit
    per_host_concurrency: int = 8      # simultaneous requests to a single host
    request_timeout: float = 15.0      # seconds per request
    max_retries: int = 2               # retries on transient network errors
    max_requests: int = 5000           # hard ceiling on total requests per scan
    user_agent: str = "sternuke/1.0 (+security-assessment)"
    verify_tls: bool = True            # never silently disable TLS verification
    allowed_hosts: Optional[List[str]] = None  # optional explicit allow-list

    def is_host_allowed(self, host: str) -> bool:
        """Return True when ``host`` may be scanned under this policy."""
        if not self.allowed_hosts:
            return True
        host = (host or "").lower()
        return any(host == h.lower() or host.endswith("." + h.lower())
                   for h in self.allowed_hosts)


# ----------------------------------------------------------------------------
# Rate limiting
# ----------------------------------------------------------------------------
class _TokenBucket:
    """A simple asyncio-friendly token bucket for global request pacing."""

    def __init__(self, rate: float, capacity: Optional[float] = None) -> None:
        self._rate = max(rate, 0.1)
        self._capacity = capacity if capacity is not None else max(rate, 1.0)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self._capacity, self._tokens + (now - self._updated) * self._rate
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(deficit)


# ----------------------------------------------------------------------------
# Async HTTP client
# ----------------------------------------------------------------------------
@dataclass
class HttpResponse:
    """Normalised view of an HTTP response used by the matcher engine."""

    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float

    @property
    def header_blob(self) -> str:
        return "\n".join(f"{k}: {v}" for k, v in self.headers.items())


class AsyncHttpClient:
    """Rate-limited, policy-aware async HTTP client.

    The client owns a single ``aiohttp.ClientSession`` and enforces the global
    and per-host concurrency limits declared by :class:`ScanPolicy`.
    """

    def __init__(self, policy: ScanPolicy, logger: Optional[Callable[[str], None]] = None):
        if aiohttp is None:
            raise RuntimeError(
                "aiohttp is required for web scanning. Install with: pip install aiohttp"
            )
        self.policy = policy
        self._log = logger or (lambda msg: None)
        self._sem = asyncio.Semaphore(policy.max_concurrency)
        self._bucket = _TokenBucket(policy.requests_per_second)
        self._host_sems: Dict[str, asyncio.Semaphore] = {}
        self._session: Optional[aiohttp.ClientSession] = None
        self._request_count = 0

    async def __aenter__(self) -> "AsyncHttpClient":
        timeout = aiohttp.ClientTimeout(total=self.policy.request_timeout)
        connector = aiohttp.TCPConnector(
            limit=self.policy.max_concurrency, ssl=None if self.policy.verify_tls else False
        )
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self.policy.user_agent},
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()

    def _host_semaphore(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_sems:
            self._host_sems[host] = asyncio.Semaphore(self.policy.per_host_concurrency)
        return self._host_sems[host]

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
    ) -> Optional[HttpResponse]:
        """Perform a single request, honouring all policy limits.

        Returns ``None`` when the request is refused by policy or fails after
        the configured number of retries.
        """
        host = urlparse(url).hostname or ""
        if not self.policy.is_host_allowed(host):
            self._log(f"[policy] refused out-of-scope host: {host}")
            return None
        if self._request_count >= self.policy.max_requests:
            self._log("[policy] max request ceiling reached; skipping further requests")
            return None

        host_sem = self._host_semaphore(host)
        async with self._sem, host_sem:
            for attempt in range(self.policy.max_retries + 1):
                await self._bucket.acquire()
                start = time.monotonic()
                try:
                    self._request_count += 1
                    assert self._session is not None
                    async with self._session.request(
                        method.upper(), url, headers=headers, data=data,
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        return HttpResponse(
                            url=str(resp.url),
                            status=resp.status,
                            headers={k: v for k, v in resp.headers.items()},
                            body=body,
                            elapsed=time.monotonic() - start,
                        )
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    if attempt >= self.policy.max_retries:
                        self._log(f"[net] {method} {url} failed: {exc}")
                        return None
                    await asyncio.sleep(0.5 * (2 ** attempt))  # backoff
        return None

    @property
    def request_count(self) -> int:
        return self._request_count


# ----------------------------------------------------------------------------
# Rule model + matcher engine
# ----------------------------------------------------------------------------
class Matcher:
    """Evaluates a single matcher block against an :class:`HttpResponse`.

    Supported matcher ``type`` values:

    * ``word``   - substring search in the chosen ``part``.
    * ``regex``  - regular-expression search in the chosen ``part``.
    * ``status`` - exact HTTP status-code match.

    ``part`` may be ``body`` (default), ``header`` or ``all``.
    ``condition`` (``and`` / ``or``) combines multiple words / patterns.
    """

    def __init__(self, spec: Dict[str, Any]):
        self.type = str(spec.get("type", "word")).lower()
        self.part = str(spec.get("part", "body")).lower()
        self.condition = str(spec.get("condition", "or")).lower()
        self.words: List[str] = list(spec.get("words", []) or [])
        self.regexes: List[re.Pattern] = [
            re.compile(p, re.IGNORECASE | re.MULTILINE) for p in (spec.get("regex", []) or [])
        ]
        self.status: List[int] = [int(s) for s in (spec.get("status", []) or [])]
        self.negative = bool(spec.get("negative", False))

    def _text(self, resp: HttpResponse) -> str:
        if self.part == "header":
            return resp.header_blob
        if self.part == "all":
            return resp.header_blob + "\n" + resp.body
        return resp.body

    def evaluate(self, resp: HttpResponse) -> Optional[str]:
        """Return matched evidence (a short string) or ``None`` if no match.

        The ``negative`` flag inverts the result (used for "must NOT contain").
        """
        matched, evidence = self._raw_evaluate(resp)
        if self.negative:
            matched = not matched
            evidence = evidence or "negative-match satisfied"
        return evidence if matched else None

    def _raw_evaluate(self, resp: HttpResponse) -> tuple[bool, str]:
        if self.type == "status":
            ok = resp.status in self.status
            return ok, (f"status={resp.status}" if ok else "")

        text = self._text(resp)
        if self.type == "regex":
            hits = [m.group(0) for p in self.regexes if (m := p.search(text))]
            need_all = self.condition == "and"
            ok = (len(hits) == len(self.regexes)) if need_all else bool(hits)
            return ok, ("; ".join(hits[:3]))[:240]

        # default: word matcher
        found = [w for w in self.words if w in text]
        need_all = self.condition == "and"
        ok = (len(found) == len(self.words)) if need_all else bool(found)
        return ok, ("; ".join(found[:5]))[:240]


class Rule:
    """A single detection rule (Nuclei-inspired, fully parsed locally).

    Example YAML::

        id: exposed-git-config
        info:
          name: Exposed .git/config
          severity: medium
          description: The .git/config file is publicly readable.
        requests:
          - method: GET
            path: ["/.git/config"]
            matchers:
              - type: word
                words: ["[core]", "repositoryformatversion"]
                condition: and
    """

    def __init__(self, spec: Dict[str, Any]):
        self.id: str = str(spec.get("id") or spec.get("name") or "unnamed-rule")
        info = spec.get("info", {}) or {}
        self.name: str = str(info.get("name", self.id))
        self.severity: str = str(info.get("severity", "info")).lower()
        if self.severity not in SEVERITIES:
            self.severity = "info"
        self.description: str = str(info.get("description", ""))
        self.remediation: str = str(info.get("remediation", ""))
        self.tags: List[str] = list(info.get("tags", []) or [])
        # A rule contains one or more request templates.
        self.requests: List[Dict[str, Any]] = spec.get("requests", spec.get("http", [])) or []

    @staticmethod
    def _build_matchers(req: Dict[str, Any]) -> List[Matcher]:
        return [Matcher(m) for m in (req.get("matchers", []) or [])]

    @staticmethod
    def _matchers_condition(req: Dict[str, Any]) -> str:
        return str(req.get("matchers-condition", req.get("matchers_condition", "or"))).lower()


class RuleEngine:
    """Loads rule files (YAML/JSON) and evaluates them against responses."""

    def __init__(self, logger: Optional[Callable[[str], None]] = None):
        self._log = logger or (lambda msg: None)
        self.rules: List[Rule] = []

    # -- loading --------------------------------------------------------------
    def load_file(self, path: str) -> int:
        """Load one rule file. Returns the number of rules added."""
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
        docs = self._parse(raw, path)
        added = 0
        for doc in docs:
            if isinstance(doc, dict) and (doc.get("id") or doc.get("requests") or doc.get("http")):
                self.rules.append(Rule(doc))
                added += 1
        self._log(f"[rules] loaded {added} rule(s) from {os.path.basename(path)}")
        return added

    def load_dir(self, directory: str) -> int:
        """Recursively load every ``.yaml``/``.yml``/``.json`` rule file."""
        total = 0
        for root, _dirs, files in os.walk(directory):
            for name in sorted(files):
                if name.lower().endswith((".yaml", ".yml", ".json")):
                    try:
                        total += self.load_file(os.path.join(root, name))
                    except Exception as exc:  # noqa: BLE001 - keep loading others
                        self._log(f"[rules] skipped {name}: {exc}")
        return total

    @staticmethod
    def _parse(raw: str, path: str) -> List[Any]:
        if path.lower().endswith(".json"):
            data = json.loads(raw)
            return data if isinstance(data, list) else [data]
        if yaml is None:
            raise RuntimeError("PyYAML is required to load YAML rules (pip install pyyaml)")
        return [d for d in yaml.safe_load_all(raw) if d is not None]

    # -- evaluation -----------------------------------------------------------
    def evaluate(self, rule: Rule, req: Dict[str, Any], resp: HttpResponse,
                 target: str) -> Optional[Finding]:
        """Evaluate one request template's matchers against a response."""
        matchers = Rule._build_matchers(req)
        if not matchers:
            return None
        results = [(m, m.evaluate(resp)) for m in matchers]
        condition = Rule._matchers_condition(req)
        matched = [ev for _m, ev in results if ev is not None]
        ok = (len(matched) == len(matchers)) if condition == "and" else bool(matched)
        if not ok:
            return None
        return Finding(
            rule_id=rule.id,
            name=rule.name,
            severity=rule.severity,
            target=target,
            matched_at=resp.url,
            evidence=" | ".join(matched)[:400],
            description=rule.description,
            remediation=rule.remediation,
            tags=rule.tags,
        )


# ----------------------------------------------------------------------------
# Web scanner (async request manager + fuzzer)
# ----------------------------------------------------------------------------
class WebScanner:
    """Drives asynchronous web/API assessment for a set of targets.

    For each target the scanner materialises every rule's request templates
    (expanding paths and payloads), issues them through :class:`AsyncHttpClient`,
    and runs the local matcher engine over the responses.
    """

    def __init__(self, policy: ScanPolicy, rule_engine: RuleEngine,
                 logger: Optional[Callable[[str], None]] = None):
        self.policy = policy
        self.rules = rule_engine
        self._log = logger or (lambda msg: None)

    # -- request template expansion ------------------------------------------
    @staticmethod
    def _base(target: str) -> str:
        if "://" not in target:
            target = "http://" + target
        return target.rstrip("/")

    def _expand_paths(self, req: Dict[str, Any]) -> List[str]:
        paths = req.get("path", req.get("paths", ["/"]))
        if isinstance(paths, str):
            paths = [paths]
        return list(paths)

    def _fuzz_parameters(self, url: str, payloads: Sequence[str]) -> List[str]:
        """Return URLs where each existing query parameter is replaced by every
        payload in turn. Used for reflected/parameter-based signatures.
        """
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params or not payloads:
            return []
        fuzzed: List[str] = []
        for idx, (key, _val) in enumerate(params):
            for payload in payloads:
                mutated = list(params)
                mutated[idx] = (key, payload)
                new_query = urlencode(mutated)
                fuzzed.append(urlunparse(parsed._replace(query=new_query)))
        return fuzzed

    async def _run_request_template(
        self, client: AsyncHttpClient, target: str, rule: Rule,
        req: Dict[str, Any], sink: Callable[[Finding], None],
    ) -> None:
        base = self._base(target)
        method = str(req.get("method", "GET")).upper()
        headers = dict(req.get("headers", {}) or {})
        body = req.get("body")
        payloads: List[str] = list(req.get("payloads", []) or [])

        urls: List[str] = []
        for path in self._expand_paths(req):
            full = base + (path if path.startswith("/") else "/" + path)
            urls.append(full)
            # Parameter fuzzing only touches URLs that already carry parameters,
            # keeping request volume bounded and predictable.
            urls.extend(self._fuzz_parameters(full, payloads))

        for url in urls:
            resp = await client.request(method, url, headers=headers, data=body)
            if resp is None:
                continue
            finding = self.rules.evaluate(rule, req, resp, target)
            if finding:
                self._log(f"[hit] {finding}")
                sink(finding)

    async def scan_target(
        self, client: AsyncHttpClient, target: str,
        sink: Callable[[Finding], None],
    ) -> None:
        tasks: List[Awaitable[None]] = []
        for rule in self.rules.rules:
            for req in rule.requests:
                tasks.append(self._run_request_template(client, target, rule, req, sink))
        if tasks:
            await asyncio.gather(*tasks)

    async def scan(self, targets: Iterable[str]) -> List[Finding]:
        """Scan every target and return the aggregated findings."""
        findings: List[Finding] = []
        sink = findings.append
        targets = list(dict.fromkeys(targets))  # de-dupe, keep order
        self._log(f"[scan] starting web assessment of {len(targets)} target(s), "
                  f"{len(self.rules.rules)} rule(s)")
        async with AsyncHttpClient(self.policy, self._log) as client:
            for target in targets:
                self._log(f"[scan] target: {target}")
                await self.scan_target(client, target, sink)
        self._log(f"[scan] complete: {len(findings)} finding(s), "
                  f"{client.request_count} request(s) sent")
        return findings


# ----------------------------------------------------------------------------
# Local filesystem crawler (blockchain repositories)
# ----------------------------------------------------------------------------
@dataclass
class SourceFile:
    path: str
    language: str
    size: int
    content: str


class RepoCrawler:
    """Walks a local directory and collects blockchain source files.

    Only reads from the local filesystem - it never fetches remote code. The
    crawler recognises Solidity (``.sol``) and Rust (``.rs``) sources and skips
    common dependency / build directories to keep the model focused on the
    project's own code.
    """

    LANGUAGES = {".sol": "solidity", ".rs": "rust"}
    SKIP_DIRS = {"node_modules", ".git", "target", "artifacts", "cache",
                 "out", "lib", "build", ".venv", "venv", "__pycache__"}

    def __init__(self, max_file_bytes: int = 512 * 1024,
                 logger: Optional[Callable[[str], None]] = None):
        self.max_file_bytes = max_file_bytes
        self._log = logger or (lambda msg: None)

    def crawl(self, root: str, languages: Optional[Sequence[str]] = None) -> List[SourceFile]:
        if not os.path.isdir(root):
            raise NotADirectoryError(f"Not a directory: {root}")
        wanted = {ext for ext, lang in self.LANGUAGES.items()
                  if not languages or lang in languages}
        collected: List[SourceFile] = []
        for cur, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for name in files:
                ext = os.path.splitext(name)[1].lower()
                if ext not in wanted:
                    continue
                full = os.path.join(cur, name)
                try:
                    size = os.path.getsize(full)
                    if size > self.max_file_bytes:
                        self._log(f"[crawl] skip (too large): {full}")
                        continue
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError as exc:
                    self._log(f"[crawl] skip {full}: {exc}")
                    continue
                collected.append(SourceFile(full, self.LANGUAGES[ext], size, content))
        self._log(f"[crawl] collected {len(collected)} source file(s) under {root}")
        return collected
