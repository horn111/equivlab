"""Stable EquivLab report construction and serialization."""

from __future__ import annotations

import hashlib
import json

from .ast_index import AstIndex
from .canonicalize import SourceDecodeError, canonicalize_source
from .rules import IMPLEMENTED_RULES, POLICY_ID, Evidence, RuleResult, evaluate_ast_rules, evaluate_src


_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _finding(result: RuleResult) -> dict[str, object]:
    return {
        "evidence": [item.as_dict() for item in sorted(result.evidence, key=lambda item: (item.line, item.symbol, item.detail))],
        "rule": result.rule,
        "severity": result.severity,
        "status": result.status,
        "summary": result.summary,
    }


def _base_report(source_url: str, source_hash: str) -> dict[str, object]:
    return {
        "failed_rules": [],
        "findings": [],
        "implemented_rules": list(IMPLEMENTED_RULES),
        "policy": POLICY_ID,
        "schema": "equivlab-report-v1",
        "severity": "LOW",
        "scope": "Twelve deterministic rule cores only; semantic supplements are not evaluated. This is not formal verification or a security guarantee.",
        "source": {"canonical_sha256": source_hash, "url": source_url},
        "status": "MEETS_BASELINE",
        "unverifiable_rules": [],
        "warning_rules": [],
    }


def _finish_report(report: dict[str, object], results: list[RuleResult]) -> dict[str, object]:
    failed = sorted(item.rule for item in results if item.status == "FAIL")
    warnings = sorted(item.rule for item in results if item.status == "WARN")
    unverifiable = sorted(item.rule for item in results if item.status == "UNVERIFIABLE")
    findings = sorted(
        (_finding(item) for item in results if item.status != "MEETS_BASELINE"),
        key=lambda item: str(item["rule"]),
    )

    if unverifiable:
        status = "UNVERIFIABLE"
    elif failed:
        status = "FAIL"
    elif warnings:
        status = "WARN"
    else:
        status = "MEETS_BASELINE"

    nonpassing = [item for item in results if item.status != "MEETS_BASELINE"]
    severity = max(
        (item.severity for item in nonpassing),
        key=lambda value: _SEVERITY_ORDER[value],
        default="LOW",
    )
    report.update(
        {
            "failed_rules": failed,
            "findings": findings,
            "severity": severity,
            "status": status,
            "unverifiable_rules": unverifiable,
            "warning_rules": warnings,
        }
    )
    payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    report["report_sha256"] = hashlib.sha256(payload).hexdigest()
    return report


def analyze_source(source: bytes | str, source_url: str, expected_sha256: str | None) -> dict[str, object]:
    try:
        canonical = canonicalize_source(source)
    except SourceDecodeError:
        report = _base_report(source_url, "")
        results = [
            RuleResult(rule, "UNVERIFIABLE", "Source is not valid UTF-8, so this rule could not be evaluated.")
            for rule in IMPLEMENTED_RULES
        ]
        return _finish_report(report, results)

    source_hash = hashlib.sha256(canonical).hexdigest()
    report = _base_report(source_url, source_hash)
    source_result = evaluate_src(source_url, expected_sha256, source_hash)
    if source_result.status == "UNVERIFIABLE":
        blocked = [
            RuleResult(rule, "UNVERIFIABLE", "Rule evaluation is not authoritative because source identity was not established.")
            for rule in IMPLEMENTED_RULES
            if rule != "SRC-01"
        ]
        return _finish_report(report, [source_result, *blocked])

    try:
        index = AstIndex.build(canonical.decode("utf-8"))
    except SyntaxError as exc:
        parse_evidence = ()
        if exc.lineno is not None:
            parse_evidence = (Evidence(exc.lineno, "<module>", "Python source could not be parsed."),)
        blocked = [
            RuleResult(rule, "UNVERIFIABLE", "Python AST facts are unavailable because source parsing failed.", parse_evidence)
            for rule in IMPLEMENTED_RULES
            if rule != "SRC-01"
        ]
        return _finish_report(report, [source_result, *blocked])

    return _finish_report(report, [source_result, *evaluate_ast_rules(index)])


def dumps_report(report: dict[str, object]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
