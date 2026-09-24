# -*- coding: utf-8 -*-
"""
sternuke.assets
===============

Bulk target ingestion and asset classification.

Operators run assessments from program *scope* lists that mix asset kinds on
different lines. This module turns raw pasted text or an uploaded ``.txt`` /
``.csv`` scope file into a typed, de-duplicated :class:`Asset` list, dynamically
identifying:

* **wildcard domains** - ``*.target.com``
* **fully-qualified domain names** - ``target.com`` or ``https://target.com``
* **IPv4 / IPv6 addresses** - ``192.0.2.10``, ``2001:db8::1``
* **explicit API endpoints** - ``https://api.target.com/v1/users``
* **smart-contract addresses** - ``0x`` + 40 hex chars

Classification is pure and dependency-free so it is fully unit-testable without
a GUI. Comment lines (``#``) and blanks are ignored.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
from urllib.parse import urlparse


class AssetType(str, Enum):
    WILDCARD_DOMAIN = "wildcard_domain"
    FQDN = "fqdn"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    API_ENDPOINT = "api_endpoint"
    CONTRACT_ADDRESS = "contract_address"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Asset:
    """A single classified target."""

    raw: str
    type: AssetType
    value: str          # normalised form (host, url, ip, or address)

    def to_dict(self) -> dict:
        return {"raw": self.raw, "type": self.type.value, "value": self.value}


_CONTRACT_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


class AssetParser:
    """Classifies raw target strings into typed :class:`Asset` objects."""

    # Columns we recognise when reading a CSV scope export.
    _CSV_KEYS = ("asset", "target", "identifier", "domain", "url", "host",
                 "endpoint", "address", "scope")

    def parse_line(self, line: str) -> Optional[Asset]:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            return None
        token = raw.split()[0].strip().strip(",")  # tolerate trailing notes/commas

        # 1) Smart-contract address.
        if _CONTRACT_RE.match(token):
            return Asset(raw, AssetType.CONTRACT_ADDRESS, token.lower())

        # 2) Wildcard domain.
        if token.startswith("*."):
            base = token[2:]
            if _DOMAIN_RE.match(base):
                return Asset(raw, AssetType.WILDCARD_DOMAIN, token.lower())

        # 3) Anything with an explicit scheme.
        if "://" in token:
            return self._classify_url(raw, token)

        # 4) Bare IP address (v4/v6).
        ip_asset = self._classify_ip(raw, token)
        if ip_asset is not None:
            return ip_asset

        # 5) host:port or host/path without scheme -> re-run as URL.
        if "/" in token or re.match(r"^[^\s/]+:\d+$", token):
            return self._classify_url(raw, "//" + token, assume_scheme=True)

        # 6) Bare domain.
        if _DOMAIN_RE.match(token):
            return Asset(raw, AssetType.FQDN, token.lower())

        return Asset(raw, AssetType.UNKNOWN, token)

    def _classify_ip(self, raw: str, token: str) -> Optional[Asset]:
        candidate = token
        # Allow bracketed IPv6 like [2001:db8::1].
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            return None
        return Asset(raw, AssetType.IPV4 if ip.version == 4 else AssetType.IPV6, str(ip))

    def _classify_url(self, raw: str, token: str, *, assume_scheme: bool = False) -> Asset:
        parsed = urlparse(token if not assume_scheme else "http:" + token)
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
        has_path = bool(parsed.path and parsed.path not in ("", "/")) or bool(parsed.query)
        # An IP host is still an IP asset unless it carries a real path.
        ip_asset = self._classify_ip(raw, host) if host else None
        if has_path:
            return Asset(raw, AssetType.API_ENDPOINT, token if not assume_scheme
                         else token.lstrip("/"))
        # host[:port] forms (no path): preserve the port in the normalised value.
        host_port = f"{host}:{port}" if port else host
        if ip_asset is not None:
            value = f"{ip_asset.value}:{port}" if port else ip_asset.value
            return Asset(raw, ip_asset.type, value)
        if host.startswith("*."):
            return Asset(raw, AssetType.WILDCARD_DOMAIN, host.lower())
        if _DOMAIN_RE.match(host):
            return Asset(raw, AssetType.FQDN, host_port.lower())
        return Asset(raw, AssetType.UNKNOWN, token)

    # -- bulk -----------------------------------------------------------------
    def parse_text(self, text: str) -> List[Asset]:
        seen: set = set()
        assets: List[Asset] = []
        for line in text.splitlines():
            asset = self.parse_line(line)
            if asset and (asset.type, asset.value) not in seen:
                seen.add((asset.type, asset.value))
                assets.append(asset)
        return assets

    def parse_csv(self, text: str) -> List[Asset]:
        """Parse CSV content, picking a recognised column or the first column."""
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
        if not rows:
            return []
        header = [h.strip().lower() for h in rows[0]]
        col = 0
        data_rows = rows
        if any(h in self._CSV_KEYS for h in header):
            col = next(i for i, h in enumerate(header) if h in self._CSV_KEYS)
            data_rows = rows[1:]
        tokens = "\n".join(r[col] for r in data_rows if len(r) > col)
        return self.parse_text(tokens)

    def parse_file(self, path: str) -> List[Asset]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        if path.lower().endswith(".csv"):
            return self.parse_csv(content)
        return self.parse_text(content)

    @staticmethod
    def summary(assets: List[Asset]) -> dict:
        counts: dict = {}
        for a in assets:
            counts[a.type.value] = counts.get(a.type.value, 0) + 1
        return counts
