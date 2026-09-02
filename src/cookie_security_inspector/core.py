"""Core cookie security analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secintel_core import (
    Classification, Confidence, Evidence, Finding, InputArtifact, Provenance, Report,
    Severity, build_environment_info, canonical_config_hash, deterministic_finding_id,
    reproducible_now, sha256_file,
)
from secintel_core.security import safe_resolve_path

from cookie_security_inspector.parser import CookieIssue, ParsedCookie, analyze_cookies, load_cookies_from_har

TOOL_NAME = "cookie-security-inspector"
TOOL_VERSION = "0.1.0"
_SEV = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


@dataclass
class AnalysisConfig:
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    max_bytes: int = 50 * 1024 * 1024


@dataclass
class AnalysisResult:
    report: Report
    cookies: list[ParsedCookie]
    issues: list[CookieIssue]


def _resolve(base: Path, p: Path | str) -> Path:
    up = Path(p)
    return up.resolve() if up.is_absolute() else safe_resolve_path(base, p)


def analyze_har(input_path: Path | str, *, config: AnalysisConfig | None = None, is_sample: bool = False) -> AnalysisResult:
    cfg = config or AnalysisConfig()
    resolved = _resolve(cfg.base_dir, input_path)
    if not resolved.is_file():
        raise ValueError(f"HAR file not found: {resolved}")

    input_hash = sha256_file(resolved, max_bytes=cfg.max_bytes)
    started = reproducible_now()
    cookies = load_cookies_from_har(resolved)
    issues = analyze_cookies(cookies)
    findings = _emit_findings(cookies, issues, input_hash=input_hash, source=str(resolved), started=started)

    ended = reproducible_now()
    report = Report(
        provenance=Provenance(
            tool_name=TOOL_NAME, tool_version=TOOL_VERSION,
            config_hash=canonical_config_hash({}),
            inputs=[InputArtifact(path=str(resolved), sha256=input_hash, size_bytes=resolved.stat().st_size)],
            analysis_started_at=started, analysis_ended_at=ended,
            environment=build_environment_info(),
        ),
        findings=findings, is_sample_data=is_sample,
        metadata={"cookie_count": len(cookies), "issue_count": len(issues)},
    )
    return AnalysisResult(report=report, cookies=cookies, issues=issues)


def _emit_findings(
    cookies: list[ParsedCookie], issues: list[CookieIssue],
    *, input_hash: str, source: str, started: Any,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.append(Finding(
        id=deterministic_finding_id("cookies-observed", input_hash, {"n": len(cookies)}),
        title=f"Cookies parsed: {len(cookies)} Set-Cookie headers",
        classification=Classification.OBSERVED,
        evidence=[Evidence(source=source, locator={"count": len(cookies)}, retrieved_at=started)],
        method="Set-Cookie header parsing", why_it_matters="Cookie inventory baseline.",
        plain_language=f"Found {len(cookies)} cookies.", severity=Severity.INFO, tags=["cookie"], timestamp=started,
    ))
    avg_score = sum(c.flag_score for c in cookies) / len(cookies) if cookies else 1.0
    findings.append(Finding(
        id=deterministic_finding_id("cookie-score-derived", input_hash, {"score": avg_score}),
        title=f"Cookie security score: {avg_score * 100:.0f}%",
        classification=Classification.DERIVED,
        evidence=[Evidence(source=source, locator={"avg_flag_score": avg_score}, retrieved_at=started)],
        method="Secure/HttpOnly/SameSite flag aggregation",
        why_it_matters="Aggregate cookie hygiene metric.", plain_language=f"Average flag compliance: {avg_score * 100:.0f}%.",
        severity=Severity.INFO if avg_score > 0.8 else Severity.MEDIUM, tags=["cookie-score"], timestamp=started,
    ))
    for issue in issues:
        findings.append(Finding(
            id=deterministic_finding_id("cookie-issue", input_hash, {"name": issue.cookie.name, "issue": issue.issue}),
            title=f"Cookie issue: {issue.cookie.name} — {issue.issue}",
            classification=Classification.INFERRED,
            confidence=Confidence(score=issue.confidence_score, rationale=issue.issue, supporting_indicators=[issue.cookie.raw[:60]]),
            evidence=[Evidence(source=source, locator={"cookie": issue.cookie.name, "url": issue.cookie.url}, retrieved_at=started)],
            method="RFC 6265 flag compliance check", why_it_matters="Insecure cookies enable session hijacking and CSRF.",
            plain_language=f"Cookie '{issue.cookie.name}': {issue.issue}.",
            severity=_SEV.get(issue.severity, Severity.MEDIUM), tags=["cookie-issue", issue.issue.lower().replace(" ", "-")],
            timestamp=started,
        ))
    return findings
