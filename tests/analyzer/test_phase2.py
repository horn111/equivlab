from __future__ import annotations

from pathlib import Path

import pytest

from equivlab.ast_index import AstIndex
from equivlab.canonicalize import SourceDecodeError, canonical_sha256, canonicalize_source
from equivlab.report import analyze_source
from equivlab.rules import (
    IMPLEMENTED_RULES,
    evaluate_auth,
    evaluate_bound,
    evaluate_consensus,
    evaluate_evidence,
    evaluate_prompt,
    evaluate_replay,
    evaluate_result,
    evaluate_src,
    evaluate_state,
    evaluate_time,
    evaluate_url,
    evaluate_value,
)


ROOT = Path(__file__).parents[2]
PAIR_ROOT = ROOT / "fixtures" / "rule_pairs"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
RULE_IDS = {
    "auth_01": "AUTH-01",
    "bound_01": "BOUND-01",
    "cons_01": "CONS-01",
    "evid_01": "EVID-01",
    "prompt_01": "PROMPT-01",
    "replay_01": "REPLAY-01",
    "result_01": "RESULT-01",
    "src_01": "SRC-01",
    "state_01": "STATE-01",
    "time_01": "TIME-01",
    "url_01": "URL-01",
    "value_01": "VALUE-01",
}


def pair_index(rule: str, outcome: str) -> AstIndex:
    return AstIndex.build((PAIR_ROOT / rule / f"{outcome}.py").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("rule", "evaluator"),
    [
        ("auth_01", evaluate_auth),
        ("bound_01", evaluate_bound),
        ("cons_01", evaluate_consensus),
        ("evid_01", evaluate_evidence),
        ("prompt_01", evaluate_prompt),
        ("replay_01", evaluate_replay),
        ("result_01", evaluate_result),
        ("state_01", evaluate_state),
        ("time_01", evaluate_time),
        ("url_01", evaluate_url),
        ("value_01", evaluate_value),
    ],
)
def test_positive_and_negative_rule_pairs(rule: str, evaluator: object) -> None:
    assert evaluator(pair_index(rule, "pass")).status == "MEETS_BASELINE"
    assert evaluator(pair_index(rule, "fail")).status == "FAIL"


def test_src_positive_and_negative_pair_metadata() -> None:
    source = (PAIR_ROOT / "src_01" / "pass.py").read_bytes()
    digest = canonical_sha256(source)
    pinned = f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/pass.py"
    unpinned = "https://raw.githubusercontent.com/equivlab/demo/main/fail.py"
    assert evaluate_src(pinned, digest, digest).status == "MEETS_BASELINE"
    assert evaluate_src(unpinned, digest, digest).status == "FAIL"


@pytest.mark.parametrize("rule", sorted(RULE_IDS))
def test_rule_pair_reports_isolate_the_intended_failure(rule: str) -> None:
    passed_source = (PAIR_ROOT / rule / "pass.py").read_bytes()
    failed_source = (PAIR_ROOT / rule / "fail.py").read_bytes()
    passed_url = f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/{rule}/pass.py"
    failed_ref = "main" if rule == "src_01" else COMMIT
    failed_url = f"https://raw.githubusercontent.com/equivlab/demo/{failed_ref}/{rule}/fail.py"

    passed = analyze_source(passed_source, passed_url, canonical_sha256(passed_source))
    failed = analyze_source(failed_source, failed_url, canonical_sha256(failed_source))

    assert passed["status"] == "MEETS_BASELINE"
    assert passed["failed_rules"] == []
    assert failed["status"] == "FAIL"
    assert failed["failed_rules"] == [RULE_IDS[rule]]


def test_existing_final_blank_lines_remain_hash_significant() -> None:
    assert canonical_sha256("value = 1\n") != canonical_sha256("value = 1\n\n")


def test_source_ordering_remains_hash_significant() -> None:
    first = "def alpha():\n    pass\n\ndef beta():\n    pass\n"
    second = "def beta():\n    pass\n\ndef alpha():\n    pass\n"
    assert canonical_sha256(first) != canonical_sha256(second)


def test_unicode_source_is_preserved_as_utf8() -> None:
    source = "message = 'Привет, 世界'"
    assert canonicalize_source(source).decode("utf-8") == source + "\n"


def test_unicode_normalization_is_not_silently_applied() -> None:
    composed = "label = 'é'\n"
    decomposed = "label = 'e\u0301'\n"
    assert canonical_sha256(composed) != canonical_sha256(decomposed)


def test_invalid_utf8_raises_in_canonicalizer() -> None:
    with pytest.raises(SourceDecodeError):
        canonicalize_source(b"\xff\xfe")


def test_invalid_utf8_report_marks_every_rule_unverifiable() -> None:
    report = analyze_source(b"\xff\xfe", "https://raw.githubusercontent.com/equivlab/demo/" + COMMIT + "/bad.py", None)
    assert report["status"] == "UNVERIFIABLE"
    assert report["unverifiable_rules"] == sorted(IMPLEMENTED_RULES)


def test_plural_url_inputs_require_an_explicit_duplicate_policy() -> None:
    without_duplicate_guard = """
from genlayer import *
class Fetcher(gl.Contract):
    @gl.public.write
    def fetch(self, urls: list[str]):
        for url in urls:
            if not url.startswith('https://raw.githubusercontent.com/'):
                raise ValueError('host')
            if len(url) > 500:
                raise ValueError('length')
        def leader():
            return gl.nondet.web.render(urls[0], mode='text')
        gl.vm.run_nondet_unsafe(leader, validator)
"""
    with_duplicate_guard = without_duplicate_guard.replace(
        "        for url in urls:\n",
        "        if len(set(urls)) != len(urls):\n            raise ValueError('duplicates')\n        for url in urls:\n",
    )
    failed = evaluate_url(AstIndex.build(without_duplicate_guard))
    passed = evaluate_url(AstIndex.build(with_duplicate_guard))
    assert failed.status == "FAIL"
    assert "duplicate policy" in failed.evidence[0].detail
    assert passed.status == "MEETS_BASELINE"


def test_consensus_callback_state_mutation_fails_state_rule() -> None:
    source = """
from genlayer import *
class Unsafe(gl.Contract):
    status: str
    @gl.public.write
    def decide(self):
        def leader():
            self.status = 'LEADER_SIDE_EFFECT'
            return gl.nondet.exec_prompt('constant')
        def validator(result):
            return True
        gl.vm.run_nondet_unsafe(leader, validator)
"""
    result = evaluate_state(AstIndex.build(source))
    assert result.status == "FAIL"
    assert "Consensus callback mutates self.status" in result.evidence[0].detail
