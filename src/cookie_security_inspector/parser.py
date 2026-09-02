"""Cookie parsing and security flag analysis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from secintel_core.security import bounded_read_file

_SESSION_NAMES = re.compile(r"(session|sess|sid|auth|token|jwt)", re.I)


@dataclass
class ParsedCookie:
    name: str
    value: str
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    path: str = "/"
    domain: str = ""
    raw: str = ""
    entry_index: int = 0
    url: str = ""

    @property
    def is_session_cookie(self) -> bool:
        return bool(_SESSION_NAMES.search(self.name))

    @property
    def flag_score(self) -> float:
        score = 0.0
        if self.secure:
            score += 1 / 3
        if self.httponly:
            score += 1 / 3
        if self.samesite.lower() in {"strict", "lax"}:
            score += 1 / 3
        return score


@dataclass
class CookieIssue:
    cookie: ParsedCookie
    issue: str
    severity: str
    confidence_score: float


def parse_set_cookie(raw: str, *, entry_index: int = 0, url: str = "") -> ParsedCookie:
    parts = [p.strip() for p in raw.split(";")]
    name_val = parts[0].split("=", 1)
    name = name_val[0].strip()
    value = name_val[1].strip() if len(name_val) > 1 else ""
    cookie = ParsedCookie(name=name, value=value, raw=raw, entry_index=entry_index, url=url)
    for part in parts[1:]:
        lower = part.lower()
        if lower == "secure":
            cookie.secure = True
        elif lower == "httponly":
            cookie.httponly = True
        elif lower.startswith("samesite="):
            cookie.samesite = part.split("=", 1)[1]
        elif lower.startswith("path="):
            cookie.path = part.split("=", 1)[1]
        elif lower.startswith("domain="):
            cookie.domain = part.split("=", 1)[1]
    return cookie


def load_cookies_from_har(path: Path) -> list[ParsedCookie]:
    data = json.loads(bounded_read_file(path, max_bytes=50 * 1024 * 1024))
    entries = data if isinstance(data, list) else data.get("log", {}).get("entries", [])
    cookies: list[ParsedCookie] = []
    for i, entry in enumerate(entries):
        url = entry.get("request", {}).get("url", "")
        for h in entry.get("response", {}).get("headers", []):
            if h.get("name", "").lower() == "set-cookie":
                cookies.append(parse_set_cookie(h["value"], entry_index=i, url=url))
    return cookies


def analyze_cookies(cookies: list[ParsedCookie]) -> list[CookieIssue]:
    issues: list[CookieIssue] = []
    for c in cookies:
        if not c.secure:
            issues.append(CookieIssue(c, "Missing Secure flag", "high" if c.is_session_cookie else "medium", 0.88))
        if not c.httponly:
            issues.append(CookieIssue(c, "Missing HttpOnly flag", "high" if c.is_session_cookie else "medium", 0.86))
        if not c.samesite:
            issues.append(CookieIssue(c, "Missing SameSite attribute", "medium", 0.80))
        elif c.samesite.lower() == "none" and not c.secure:
            issues.append(CookieIssue(c, "SameSite=None requires Secure", "high", 0.92))
    return issues
