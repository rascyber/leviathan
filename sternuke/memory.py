# -*- coding: utf-8 -*-
"""
sternuke.memory
===============

Local vector memory and case-based reasoning for the sternuke agent.

This module gives sternuke a *strategic intuition*: before probing a target it
recalls historically relevant weakness patterns (generic CVE-class write-ups,
public bug-bounty report summaries, past successful footprints) and surfaces the
most similar ones to steer payload generation.

Design constraints
------------------
* **Zero heavy dependencies.** Embeddings are computed with a deterministic,
  hashing-based character/word n-gram vectoriser. ``numpy`` is used when present
  for speed but the module falls back to pure-Python vector math, so there is no
  external vector database to install.
* **Local only.** The store persists to a single JSON file on disk. Nothing is
  sent anywhere.
* **Educational knowledge.** The seed corpus contains generic, defensive
  descriptions of well-known vulnerability *classes* - the sort of material in
  public advisories and OWASP guidance - not weaponised exploit code.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Sequence, Tuple

try:
    import numpy as _np
    _HAS_NUMPY = True
except ImportError:  # pragma: no cover - pure-python fallback path
    _np = None
    _HAS_NUMPY = False


EMBED_DIM = 256
_TOKEN_RE = re.compile(r"[a-z0-9_]+")


# ---------------------------------------------------------------------------
# Deterministic hashing embedder (no external model required)
# ---------------------------------------------------------------------------
class HashingEmbedder:
    """Turns free text into a fixed-length L2-normalised vector.

    The embedder combines word tokens and character tri-grams, hashing each
    feature into one of ``dim`` buckets. It is deterministic and language and
    dependency free, which is exactly what we want for a portable, auditable
    local memory.
    """

    def __init__(self, dim: int = EMBED_DIM) -> None:
        self.dim = dim

    def _features(self, text: str) -> List[str]:
        text = text.lower()
        words = _TOKEN_RE.findall(text)
        feats: List[str] = list(words)
        # Character tri-grams over a compacted form capture lexical similarity
        # even when wording differs.
        compact = re.sub(r"\s+", " ", text)
        for i in range(len(compact) - 2):
            feats.append("§" + compact[i:i + 3])
        return feats

    @staticmethod
    def _bucket(feature: str, dim: int) -> int:
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        return int.from_bytes(digest, "little") % dim

    def embed(self, text: str) -> List[float]:
        vec = [0.0] * self.dim
        for feat in self._features(text):
            vec[self._bucket(feat, self.dim)] += 1.0
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            return vec
        return [v / norm for v in vec]


# ---------------------------------------------------------------------------
# Similarity helpers (numpy-accelerated when available)
# ---------------------------------------------------------------------------
def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity of two (assumed L2-normalised) vectors."""
    if _HAS_NUMPY:
        va, vb = _np.asarray(a, dtype=float), _np.asarray(b, dtype=float)
        denom = float(_np.linalg.norm(va) * _np.linalg.norm(vb))
        return float(va.dot(vb) / denom) if denom else 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


# ---------------------------------------------------------------------------
# Records + store
# ---------------------------------------------------------------------------
@dataclass
class MemoryRecord:
    """A single recalled case: a vulnerability pattern or past footprint."""

    id: str
    title: str
    text: str
    domain: str = "web"                       # web | blockchain
    tech: List[str] = field(default_factory=list)   # technology fingerprints
    severity: str = "medium"
    strategy: str = ""                        # how the pattern was probed (advisory)
    source: str = "seed"                      # seed | scan | user
    vector: List[float] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class Recall:
    """A memory hit with its similarity score."""

    record: MemoryRecord
    score: float


class VectorMemory:
    """A lightweight, persistent, local vector store with cosine retrieval."""

    def __init__(self, path: Optional[str] = None, dim: int = EMBED_DIM,
                 logger=None) -> None:
        self.path = path
        self.embedder = HashingEmbedder(dim)
        self._log = logger or (lambda msg: None)
        self.records: List[MemoryRecord] = []
        if path and os.path.exists(path):
            self.load(path)

    # -- persistence ---------------------------------------------------------
    def load(self, path: str) -> int:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.records = [MemoryRecord(**r) for r in data.get("records", [])]
        self._log(f"[memory] loaded {len(self.records)} record(s) from {path}")
        return len(self.records)

    def save(self, path: Optional[str] = None) -> str:
        target = path or self.path
        if not target:
            raise ValueError("No path configured for VectorMemory.save()")
        os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump({"records": [r.to_dict() for r in self.records]}, fh, indent=2)
        self._log(f"[memory] saved {len(self.records)} record(s) -> {target}")
        return target

    # -- mutation ------------------------------------------------------------
    def add(self, record: MemoryRecord) -> MemoryRecord:
        if not record.vector:
            record.vector = self.embedder.embed(f"{record.title}\n{record.text}\n"
                                                f"{' '.join(record.tech)}")
        self.records.append(record)
        return record

    def remember_finding(self, *, title: str, text: str, domain: str,
                         tech: Optional[List[str]] = None, severity: str = "medium",
                         strategy: str = "") -> MemoryRecord:
        """Persist a fresh footprint discovered during a scan for future recall."""
        rec = MemoryRecord(
            id=hashlib.blake2b(f"{title}{time.time()}".encode(), digest_size=6).hexdigest(),
            title=title, text=text, domain=domain, tech=tech or [],
            severity=severity, strategy=strategy, source="scan",
        )
        return self.add(rec)

    # -- retrieval -----------------------------------------------------------
    def query(self, text: str, *, top_k: int = 5, domain: Optional[str] = None,
              min_score: float = 0.05) -> List[Recall]:
        """Return the ``top_k`` most similar records to ``text``."""
        qvec = self.embedder.embed(text)
        scored: List[Recall] = []
        for rec in self.records:
            if domain and rec.domain != domain:
                continue
            scored.append(Recall(rec, cosine(qvec, rec.vector)))
        scored.sort(key=lambda r: r.score, reverse=True)
        return [r for r in scored if r.score >= min_score][:top_k]

    def strategic_intuition(self, tech_profile: Sequence[str], *, domain: str,
                            top_k: int = 5) -> List[Recall]:
        """Match a target's technology profile against remembered cases.

        ``tech_profile`` is a list of fingerprints (server banners, frameworks,
        contract primitives). Returns advisory strategies to guide, not dictate,
        payload generation.
        """
        profile_text = " ".join(tech_profile)
        recalls = self.query(profile_text, top_k=top_k, domain=domain)
        if recalls:
            self._log(f"[memory] recalled {len(recalls)} relevant case(s) for "
                      f"profile: {profile_text[:80]}")
        return recalls


# ---------------------------------------------------------------------------
# Seed corpus - generic, defensive knowledge of common weakness classes
# ---------------------------------------------------------------------------
def _seed_records() -> List[MemoryRecord]:
    seeds: List[Tuple[str, str, str, List[str], str, str]] = [
        # (title, text, domain, tech, severity, strategy)
        ("IDOR in REST object references",
         "Insecure direct object reference: an endpoint exposes a numeric or "
         "guessable identifier and does not verify that the authenticated user "
         "owns the referenced object. Common in /api/*/{id} handlers.",
         "web", ["rest", "api", "json"], "high",
         "Enumerate object ids across two authenticated sessions and compare "
         "authorization outcomes; a leak is confirmed when B reads A's object."),
        ("Business-logic race condition on balance/quantity",
         "Time-of-check to time-of-use flaw where concurrent requests to a "
         "stateful action (checkout, redeem, transfer) are processed before a "
         "shared counter is decremented, allowing double-spend or over-draw.",
         "web", ["cart", "checkout", "wallet", "coupon"], "high",
         "Fire N concurrent identical state-changing requests and observe "
         "whether the invariant (stock/balance) is violated."),
        ("Parameter pollution with negative or zero quantities",
         "Server trusts a client-supplied quantity/amount without validating "
         "sign or range, so a negative value inverts a debit into a credit, or "
         "duplicate parameters bypass validation on one copy.",
         "web", ["cart", "checkout", "payment"], "high",
         "Submit negative, zero and duplicated quantity/amount fields and check "
         "whether totals or balances move in the attacker's favour."),
        ("Authorization bypass via role/tenant confusion",
         "Access control checks the presence of a session but not its role or "
         "tenant, so lower-privilege users reach admin or cross-tenant actions.",
         "web", ["rbac", "multi-tenant", "admin"], "high",
         "Replay privileged requests with a low-privilege token and with the "
         "auth header removed to map which checks are actually enforced."),
        ("Server-side template injection (SSTI)",
         "User input is concatenated into a server-side template, allowing "
         "expression evaluation. Fingerprints include Jinja2, Twig, Freemarker.",
         "web", ["jinja2", "twig", "freemarker", "template"], "critical",
         "Probe with benign arithmetic markers in template syntax and confirm "
         "server-side evaluation before reporting; never run destructive code."),
        ("JWT algorithm confusion / alg=none",
         "Token validation accepts the 'none' algorithm or confuses HS256 and "
         "RS256, letting an attacker forge claims.",
         "web", ["jwt", "auth", "oauth"], "high",
         "Inspect token header handling by presenting a re-signed token and an "
         "alg=none token against a test account."),
        ("Reentrancy: state update after external value transfer",
         "A contract sends value or calls an external address before updating "
         "its own accounting, so the callee re-enters the function and drains "
         "funds. Classic in withdraw() patterns and ERC777 hooks.",
         "blockchain", ["solidity", "withdraw", "call", "erc777"], "critical",
         "Statically confirm that a state write follows an external call within "
         "the same function; recommend checks-effects-interactions or a guard."),
        ("Unchecked delegatecall / upgradeable proxy takeover",
         "delegatecall to an attacker-influenced address executes foreign code "
         "in the caller's storage context, enabling proxy/storage takeover.",
         "blockchain", ["solidity", "delegatecall", "proxy", "upgradeable"], "critical",
         "Flag delegatecall targets that are not immutable and trace who can set "
         "the implementation slot."),
        ("Integer overflow/underflow (pre-0.8 or unchecked blocks)",
         "Arithmetic without SafeMath on Solidity <0.8, or inside 'unchecked' "
         "blocks, wraps around and corrupts balances.",
         "blockchain", ["solidity", "unchecked", "math"], "high",
         "Identify arithmetic on user-controlled amounts lacking range checks."),
        ("Missing signer / owner check on privileged instruction (Solana)",
         "A Solana program instruction mutates state or moves lamports without "
         "verifying is_signer / expected owner on the relevant accounts.",
         "blockchain", ["rust", "solana", "cpi", "signer"], "critical",
         "Map instructions that change state and confirm each asserts signer and "
         "account ownership before acting."),
        ("Flash-loan-assisted price/oracle manipulation",
         "A protocol reads a spot price from a manipulable source; an atomic "
         "flash loan skews the pool within one transaction to mis-price actions.",
         "blockchain", ["solidity", "defi", "oracle", "flashloan"], "critical",
         "Flag functions that read spot reserves for pricing without a TWAP or "
         "external oracle, especially when invoked alongside external calls."),
    ]
    embedder = HashingEmbedder()
    records: List[MemoryRecord] = []
    for i, (title, text, domain, tech, severity, strategy) in enumerate(seeds):
        rec = MemoryRecord(
            id=f"seed-{i:03d}", title=title, text=text, domain=domain,
            tech=tech, severity=severity, strategy=strategy, source="seed",
        )
        rec.vector = embedder.embed(f"{title}\n{text}\n{' '.join(tech)}")
        records.append(rec)
    return records


def build_default_memory(path: Optional[str] = None, logger=None) -> VectorMemory:
    """Return a :class:`VectorMemory` pre-loaded with the seed corpus.

    If ``path`` exists it is loaded as-is; otherwise the seed corpus is
    installed and (when a path is given) persisted.
    """
    mem = VectorMemory(path=path, logger=logger)
    if not mem.records:
        for rec in _seed_records():
            mem.add(rec)
        if path:
            mem.save(path)
    return mem
