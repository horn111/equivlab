from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

from equivlab.ast_index import AstIndex
from equivlab.call_paths import CallPathAnalyzer
from equivlab.canonicalize import canonical_sha256, canonicalize_source
from equivlab.cli import main
from equivlab.report import analyze_source, dumps_report


ROOT = Path(__file__).parents[2]
COMMIT = "0123456789abcdef0123456789abcdef01234567"
ALL_RULES = [
    "AUTH-01",
    "BOUND-01",
    "CONS-01",
    "EVID-01",
    "PROMPT-01",
    "REPLAY-01",
    "RESULT-01",
    "SRC-01",
    "STATE-01",
    "TIME-01",
    "URL-01",
    "VALUE-01",
]


def fixture(name: str) -> bytes:
    return (ROOT / "fixtures" / name / "contract.py").read_bytes()


def pinned_url(name: str) -> str:
    return f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/{name}/contract.py"


def report_for(name: str) -> dict[str, object]:
    source = fixture(name)
    return analyze_source(source, pinned_url(name), canonical_sha256(source))


def test_policy_declares_all_deterministic_rules_as_implemented() -> None:
    policy = json.loads((ROOT / "policies" / "gl-consensus-baseline-2.json").read_text(encoding="utf-8"))
    implemented = sorted(rule["id"] for rule in policy["rules"] if rule["implemented"])
    assert implemented == ALL_RULES
    assert "public consensus path" in policy["status_meanings"]["MEETS_BASELINE"]


def test_canonicalization_normalizes_bom_crlf_and_final_lf() -> None:
    crlf = b"\xef\xbb\xbfvalue = 1\r\n"
    lf_without_final = "value = 1"
    assert canonicalize_source(crlf) == b"value = 1\n"
    assert canonical_sha256(crlf) == canonical_sha256(lf_without_final)


def test_ast_index_records_public_methods_consensus_and_transfers() -> None:
    backdoor = AstIndex.build(canonicalize_source(fixture("backdoored_tip_jar")).decode())
    assert [(item.qualname, item.public_kind) for item in backdoor.public_write_functions] == [
        ("TipJar.tip", "payable"),
        ("TipJar.withdraw_to", "write"),
    ]
    assert len(backdoor.functions["TipJar.withdraw_to"].transfers) == 1

    checker = AstIndex.build(canonicalize_source(fixture("schema_only_fact_checker")).decode())
    assert len(checker.functions["SchemaOnlyFactChecker.check"].consensus_calls) == 1


def test_backdoored_tip_jar_fails_auth_and_value_acceptance_criterion() -> None:
    report = report_for("backdoored_tip_jar")
    assert report["status"] == "FAIL"
    assert report["severity"] == "CRITICAL"
    assert report["failed_rules"] == ["AUTH-01", "VALUE-01"]
    assert report["unverifiable_rules"] == ["CONS-01"]
    assert [finding["rule"] for finding in report["findings"]] == ["AUTH-01", "CONS-01", "VALUE-01"]


def test_schema_only_validator_fails_consensus_independence() -> None:
    report = report_for("schema_only_fact_checker")
    assert report["status"] == "FAIL"
    assert report["failed_rules"] == ["CONS-01", "EVID-01"]


def test_hardened_fixture_meets_the_named_deterministic_baseline() -> None:
    report = report_for("hardened_fact_checker")
    assert report["status"] == "MEETS_BASELINE"
    assert report["scope"] == "Twelve deterministic rule cores only; semantic supplements are not evaluated. This is not formal verification or a security guarantee."
    assert report["severity"] == "LOW"
    assert report["failed_rules"] == []
    assert report["findings"] == []


def test_hash_mismatch_is_unverifiable_and_blocks_ast_verdicts() -> None:
    source = fixture("backdoored_tip_jar")
    report = analyze_source(source, pinned_url("backdoored_tip_jar"), "0" * 64)
    assert report["status"] == "UNVERIFIABLE"
    assert report["failed_rules"] == []
    assert report["unverifiable_rules"] == ALL_RULES


def test_unpinned_source_url_is_a_policy_failure() -> None:
    source = fixture("hardened_fact_checker")
    url = "https://raw.githubusercontent.com/equivlab/demo/main/contract.py"
    report = analyze_source(source, url, canonical_sha256(source))
    assert report["status"] == "FAIL"
    assert report["failed_rules"] == ["SRC-01"]


def test_malformed_python_is_unverifiable_for_ast_rules() -> None:
    source = b"class Broken(:\n"
    report = analyze_source(source, pinned_url("broken"), canonical_sha256(source))
    assert report["status"] == "UNVERIFIABLE"
    assert report["failed_rules"] == []
    assert report["unverifiable_rules"] == [rule for rule in ALL_RULES if rule != "SRC-01"]


def test_plain_python_file_is_explicitly_unverifiable_as_a_non_contract() -> None:
    source = b"def helper():\n    return 1\n"
    report = analyze_source(source, pinned_url("plain_python"), canonical_sha256(source))
    assert report["status"] == "UNVERIFIABLE"
    assert report["failed_rules"] == []
    assert report["unverifiable_rules"] == [rule for rule in ALL_RULES if rule != "SRC-01"]
    finding = next(item for item in report["findings"] if item["rule"] == "CONS-01")
    assert finding["summary"] == "The audited file is not a recognizable GenLayer write contract."


def test_genlayer_contract_without_public_consensus_path_is_unverifiable() -> None:
    source = b"""
from genlayer import *
class Storage(gl.Contract):
    value: int
    @gl.public.write
    def set_value(self, value: int):
        self.value = value
"""
    report = analyze_source(source, pinned_url("storage"), canonical_sha256(source))
    assert report["status"] == "UNVERIFIABLE"
    assert report["unverifiable_rules"] == ["CONS-01"]
    finding = next(item for item in report["findings"] if item["rule"] == "CONS-01")
    assert "no run_nondet_unsafe consensus path is reachable" in finding["summary"]


def test_dead_consensus_helper_does_not_make_contract_verifiable() -> None:
    source = b"""
from genlayer import *
class Probe(gl.Contract):
    @gl.public.write
    def check(self):
        return 1
    def dead_path(self):
        gl.vm.run_nondet_unsafe(lambda: 1, lambda result: True)
"""
    report = analyze_source(source, pinned_url("dead_path"), canonical_sha256(source))
    assert report["status"] == "UNVERIFIABLE"
    assert report["unverifiable_rules"] == ["CONS-01"]


def test_authority_guard_propagates_into_transfer_helper() -> None:
    source = b"""
from genlayer import *
class Vault(gl.Contract):
    def __init__(self):
        self.owner = gl.message.sender_address
    def _send(self, target):
        gl.chain.Account(Address(target)).emit_transfer(value=self.balance)
    @gl.public.write
    def withdraw(self, target):
        sender = gl.message.sender_address
        if sender != self.owner:
            raise ValueError('owner only')
        self._send(target)
"""
    index = AstIndex.build(canonicalize_source(source).decode())
    paths = CallPathAnalyzer(index).transfer_paths()
    assert len(paths) == 1
    assert paths[0].guarded is True
    report = analyze_source(source, pinned_url("vault"), canonical_sha256(source))
    assert report["status"] == "UNVERIFIABLE"
    assert report["unverifiable_rules"] == ["CONS-01"]


def test_report_json_and_hash_are_stable() -> None:
    first = report_for("backdoored_tip_jar")
    second = report_for("backdoored_tip_jar")
    assert dumps_report(first) == dumps_report(second)

    claimed_hash = first["report_sha256"]
    unsigned = dict(first)
    del unsigned["report_sha256"]
    payload = json.dumps(unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    assert claimed_hash == hashlib.sha256(payload).hexdigest()


def test_cli_emits_the_same_stable_report_and_failure_exit_code() -> None:
    path = ROOT / "fixtures" / "backdoored_tip_jar" / "contract.py"
    source = path.read_bytes()
    output = io.StringIO()
    exit_code = main(
        [str(path), "--url", pinned_url("backdoored_tip_jar"), "--sha256", canonical_sha256(source)],
        stdout=output,
    )
    assert exit_code == 1
    assert json.loads(output.getvalue()) == report_for("backdoored_tip_jar")
