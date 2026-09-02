"""Tests."""

from pathlib import Path

from cookie_security_inspector.core import analyze_har
from cookie_security_inspector.parser import parse_set_cookie

FIXTURES = Path(__file__).resolve().parent.parent / "sample_data"


class TestCookieInspector:
    def test_parses_cookies(self) -> None:
        r = analyze_har(FIXTURES / "sample_har_entries.json")
        assert len(r.cookies) >= 2

    def test_finds_issues(self) -> None:
        r = analyze_har(FIXTURES / "sample_har_entries.json")
        assert len(r.issues) >= 1

    def test_parse_set_cookie(self) -> None:
        c = parse_set_cookie("session=abc; Secure; HttpOnly; SameSite=Strict")
        assert c.secure and c.httponly and c.samesite == "Strict"
