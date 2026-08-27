from __future__ import annotations

from pathlib import Path

import pytest

from equivlab.ast_index import AstIndex
from equivlab.canonicalize import canonical_sha256
from equivlab.report import analyze_source
from equivlab.rules import evaluate_auth, evaluate_value


ROOT = Path(__file__).parents[2]
AUTH_FIXTURES = ROOT / "fixtures" / "rule_pairs" / "auth_01" / "adversarial"
VALUE_FIXTURES = ROOT / "fixtures" / "rule_pairs" / "value_01" / "adversarial"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def load_index(root: Path, name: str) -> AstIndex:
    return AstIndex.build((root / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "name",
    [
        "inverted_assert.py",
        "inverted_if.py",
        "inverted_else.py",
        "tautology.py",
        "or_escape.py",
        "partial_rejection.py",
        "conditional_raise.py",
        "reassigned_alias.py",
        "optional_nested_guard.py",
        "transfer_before_raise.py",
        "assert_message_transfer.py",
    ],
)
def test_misleading_or_inverted_authority_conditions_fail_closed_analysis(name: str) -> None:
    result = evaluate_auth(load_index(AUTH_FIXTURES, name))
    assert result.status == "FAIL"
    assert result.evidence


@pytest.mark.parametrize(
    "name",
    [
        "valid_assert.py",
        "valid_conjunction.py",
        "valid_or_rejection.py",
        "valid_membership.py",
    ],
)
def test_proven_fail_closed_authority_conditions_still_meet_baseline(name: str) -> None:
    result = evaluate_auth(load_index(AUTH_FIXTURES, name))
    assert result.status == "MEETS_BASELINE"


def test_permissionless_withdraw_inverted_assert_fails_auth_and_value() -> None:
    path = AUTH_FIXTURES / "inverted_assert.py"
    source = path.read_bytes()
    source_url = f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/inverted_assert.py"

    report = analyze_source(source, source_url, canonical_sha256(source))

    assert report["status"] == "FAIL"
    assert report["failed_rules"] == ["AUTH-01", "VALUE-01"]


def test_reversed_membership_is_not_treated_as_authority() -> None:
    source = """
from genlayer import *
class Vault(gl.Contract):
    admins: TreeMap[Address, bool]
    @gl.public.write
    def withdraw(self, recipient: str):
        assert self.admins in gl.message.sender_address
        gl.eth_transfer(Address(recipient), self.balance)
"""
    assert evaluate_auth(AstIndex.build(source)).status == "FAIL"


@pytest.mark.parametrize("name", ["sender_recipient.py", "message_value_recipient.py"])
def test_unguarded_caller_selected_recipient_fails_value(name: str) -> None:
    result = evaluate_value(load_index(VALUE_FIXTURES, name))
    assert result.status == "FAIL"
    assert "caller input" in result.evidence[0].detail


def test_nondeterministic_recipient_fails_value_even_after_authority_guard() -> None:
    index = load_index(VALUE_FIXTURES, "nondeterministic_recipient.py")
    assert evaluate_auth(index).status == "MEETS_BASELINE"
    result = evaluate_value(index)
    assert result.status == "FAIL"
    assert "nondeterministic output" in result.evidence[0].detail
