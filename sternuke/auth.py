# -*- coding: utf-8 -*-
"""
sternuke.auth
=============

Form-based authentication for authenticated scans.

Rather than pasting a session cookie, an operator can supply credentials and a
login URL; :class:`FormAuthenticator` performs the login the way a browser would
- it GETs the login page, carries forward any hidden fields (which covers
anti-CSRF tokens such as DVWA's ``user_token``), POSTs the credentials, and
captures the resulting session cookie. The returned ``Cookie`` header is then
applied to every request of the scan/fuzz/chain.

This only automates a standard login against a target you are authorised to
test; it performs no credential guessing or brute force.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional
from urllib.parse import urlencode

from .engine import AsyncHttpClient, ScanPolicy
from .state_engine import SessionStateManager

Logger = Callable[[str], None]

_HIDDEN_INPUT = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR_TYPE = re.compile(r"""type\s*=\s*['"]?hidden['"]?""", re.IGNORECASE)
_ATTR_NAME = re.compile(r"""name\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_ATTR_VALUE = re.compile(r"""value\s*=\s*['"]([^'"]*)['"]""", re.IGNORECASE)


class AuthError(RuntimeError):
    """Raised when authentication cannot be completed."""


@dataclass
class LoginConfig:
    """Describes a form login.

    Defaults target the common ``username``/``password`` pattern and include a
    ``Login=Login`` submit field (used by DVWA and many PHP apps). Hidden form
    fields on the login page - including CSRF tokens - are captured and replayed
    automatically, so ``csrf_field`` rarely needs to be set explicitly.
    """

    login_url: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    submit_field: Optional[str] = "Login"
    submit_value: str = "Login"
    csrf_field: Optional[str] = None            # informational; hidden fields auto-captured
    extra_fields: Dict[str, str] = field(default_factory=dict)
    extra_cookies: Dict[str, str] = field(default_factory=dict)  # e.g. {"security": "low"}
    method: str = "POST"


def _hidden_inputs(html: str) -> Dict[str, str]:
    """Extract ``name -> value`` for every hidden input in ``html``."""
    fields: Dict[str, str] = {}
    for tag in _HIDDEN_INPUT.finditer(html or ""):
        raw = tag.group(0)
        if not _ATTR_TYPE.search(raw):
            continue
        name = _ATTR_NAME.search(raw)
        if not name:
            continue
        value = _ATTR_VALUE.search(raw)
        fields[name.group(1)] = value.group(1) if value else ""
    return fields


class FormAuthenticator:
    """Performs a form login and returns an authenticated ``Cookie`` header."""

    def __init__(self, policy: Optional[ScanPolicy] = None,
                 logger: Optional[Logger] = None) -> None:
        # A gentle policy: login is a couple of requests, not a scan.
        self.policy = policy or ScanPolicy(max_concurrency=4, requests_per_second=10)
        self._log = logger or (lambda msg: None)

    async def authenticate(self, cfg: LoginConfig) -> Dict[str, str]:
        """Log in and return ``{"Cookie": "..."}`` for the established session."""
        vault = SessionStateManager()
        async with AsyncHttpClient(self.policy, self._log) as client:
            page = await client.request("GET", cfg.login_url)
            if page is None:
                raise AuthError(f"could not reach login page: {cfg.login_url}")
            vault.ingest_response(page)

            form: Dict[str, str] = _hidden_inputs(page.body)   # carries CSRF token
            form[cfg.username_field] = cfg.username
            form[cfg.password_field] = cfg.password
            form.update(cfg.extra_fields)
            if cfg.submit_field:
                form[cfg.submit_field] = cfg.submit_value or cfg.submit_field

            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            headers.update(vault.cookie_header())   # send the session cookie from the GET
            post = await client.request(cfg.method, cfg.login_url,
                                        headers=headers, data=urlencode(form))
            if post is not None:
                vault.ingest_response(post)

        # Optional cookies the app expects (e.g. DVWA security level).
        for name, value in cfg.extra_cookies.items():
            vault.set_cookie(name, value)

        if not vault.cookies:
            raise AuthError("login produced no session cookie "
                            "(check the login URL, field names or credentials)")

        final_url = str(post.url).lower() if post else ""
        body = (post.body if post else "").lower()
        looks_failed = ("login failed" in body or "incorrect" in body or
                        (final_url.endswith("login.php")))
        note = "  (warning: response still resembles the login page - verify creds)" \
            if looks_failed else ""
        self._log(f"[auth] logged in as {cfg.username!r}; "
                  f"captured cookie(s): {', '.join(vault.cookies)}{note}")
        return vault.cookie_header()
