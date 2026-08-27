"""GenLayer direct-mode checks.

These tests activate when genlayer-test is installed. The dependency is not
bundled with EquivLab and is intentionally not replaced by the pure Python
contract stub tests in tests/contract.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


pytest.importorskip("gltest", reason="genlayer-test==0.29.2 is required for direct mode")

from gltest.direct import sdk_loader as _sdk_loader

# genlayer-test 0.29.2 unlinks an fd still duplicated to stdin. Windows keeps
# that handle open, so tolerate only the resulting PermissionError.
_original_unlink = os.unlink


def _tolerant_unlink(path, *args, **kwargs):
    try:
        _original_unlink(path, *args, **kwargs)
    except PermissionError:
        pass


os.unlink = _tolerant_unlink


ROOT = Path(__file__).parents[2]
_sdk_loader.CACHE_DIR = ROOT / ".gltest-cache"
CONTRACT_PATH = "contracts/consensus_safety_registry.py"
RUNTIME = "v0.2.16"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
POLICY = "gl-consensus-baseline-1"


def canonical_source(source: str) -> str:
    text = source.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    return text if text.endswith("\n") else text + "\n"


def source_hash(source: str) -> str:
    import hashlib

    return hashlib.sha256(canonical_source(source).encode("utf-8")).hexdigest()


def fixture_source(name: str) -> str:
    return (ROOT / "fixtures" / name / "contract.py").read_text(encoding="utf-8")


def pinned_url(name: str) -> str:
    return f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/{name}/contract.py"


def install_source(vm, name: str, source: str) -> None:
    escaped = name.replace("_", r"\_")
    vm.mock_web(rf".*{escaped}.*", {"status": 200, "body": source})


def request(contract, name: str, source: str, supersedes: int | None = None):
    args = (pinned_url(name), source_hash(source), POLICY)
    if supersedes is None:
        return contract.request_audit(*args)
    return contract.request_superseding_audit(*args, supersedes)


def deploy_registry(direct_deploy):
    """Deploy cleanly across tests despite genlayer-test 0.29.2 SDK state leakage."""
    try:
        import genlayer.gl.genvm_contracts as genvm_contracts
    except ImportError:
        pass
    else:
        genvm_contracts.__known_contract__ = None
    return direct_deploy(CONTRACT_PATH, sdk_version=RUNTIME)


def test_direct_demo_statuses(direct_vm, direct_deploy):
    contract = deploy_registry(direct_deploy)

    backdoor = fixture_source("backdoored_tip_jar")
    install_source(direct_vm, "backdoored_tip_jar", backdoor)
    backdoor_id = request(contract, "backdoored_tip_jar", backdoor)
    assert json.loads(contract.get_report(backdoor_id))["failed_rules"] == ["AUTH-01", "VALUE-01"]

    schema_only = fixture_source("schema_only_fact_checker")
    install_source(direct_vm, "schema_only_fact_checker", schema_only)
    schema_id = request(contract, "schema_only_fact_checker", schema_only)
    assert json.loads(contract.get_report(schema_id))["failed_rules"] == ["CONS-01", "EVID-01"]

    hardened = fixture_source("hardened_fact_checker")
    install_source(direct_vm, "hardened_fact_checker", hardened)
    hardened_id = request(contract, "hardened_fact_checker", hardened)
    assert json.loads(contract.get_report(hardened_id))["status"] == "MEETS_BASELINE"


def test_direct_validator_accepts_matching_independent_audit(direct_vm, direct_deploy):
    contract = deploy_registry(direct_deploy)
    source = fixture_source("hardened_fact_checker")
    install_source(direct_vm, "hardened_fact_checker", source)
    request(contract, "hardened_fact_checker", source)

    assert direct_vm.run_validator() is True


def test_direct_validator_rejects_source_disagreement(direct_vm, direct_deploy):
    contract = deploy_registry(direct_deploy)
    source = fixture_source("hardened_fact_checker")
    install_source(direct_vm, "hardened_fact_checker", source)
    request(contract, "hardened_fact_checker", source)

    direct_vm.clear_mocks()
    install_source(direct_vm, "hardened_fact_checker", source + "\n# changed after leader fetch\n")
    assert direct_vm.run_validator() is False


def test_direct_hash_mismatch_is_unverifiable(direct_vm, direct_deploy):
    contract = deploy_registry(direct_deploy)
    source = fixture_source("hardened_fact_checker")
    install_source(direct_vm, "hardened_fact_checker", source)

    audit_id = contract.request_audit(pinned_url("hardened_fact_checker"), "0" * 64, POLICY)

    assert json.loads(contract.get_report(audit_id))["status"] == "UNVERIFIABLE"


def test_direct_full_source_identity_keeps_mirrors_independent(direct_vm, direct_deploy):
    contract = deploy_registry(direct_deploy)
    source = fixture_source("hardened_fact_checker")
    install_source(direct_vm, "mirror_one", source)
    first = request(contract, "mirror_one", source)
    install_source(direct_vm, "mirror_two", source)
    second = request(contract, "mirror_two", source)

    assert first == 0 and second == 1
    assert contract.get_latest(pinned_url("mirror_one"), source_hash(source), POLICY) == "0"
    assert contract.get_latest(pinned_url("mirror_two"), source_hash(source), POLICY) == "1"


def test_direct_inverted_assert_is_not_an_authority_guard(direct_vm, direct_deploy):
    contract = deploy_registry(direct_deploy)
    source = '''from genlayer import *

class Vault(gl.Contract):
    owner: Address

    @gl.public.write
    def withdraw(self, recipient: str):
        assert gl.message.sender_address != self.owner
        gl.eth_transfer(Address(recipient), self.balance)
'''
    install_source(direct_vm, "inverted_assert", source)
    audit_id = request(contract, "inverted_assert", source)

    stored = json.loads(contract.get_report(audit_id))
    assert stored["status"] == "FAIL"
    assert stored["failed_rules"] == ["AUTH-01", "VALUE-01"]


def test_direct_duplicate_challenge_and_supersession(direct_vm, direct_deploy):
    contract = deploy_registry(direct_deploy)
    source = fixture_source("hardened_fact_checker")
    install_source(direct_vm, "hardened_fact_checker", source)
    first = request(contract, "hardened_fact_checker", source)

    with direct_vm.expect_revert("duplicate source identity and policy audit"):
        request(contract, "hardened_fact_checker", source)

    assert contract.challenge(first, "a" * 64) == "0"
    assert contract.challenge(first, "b" * 64) == "1"
    stored_first = json.loads(contract.get_audit(first))
    assert stored_first["challenged"] is True
    assert stored_first["challenge_count"] == 2
    assert contract.get_challenge_count(first) == 2
    assert json.loads(contract.get_audit_challenge(first, 0))["reason_hash"] == "a" * 64
    assert json.loads(contract.get_challenge(1))["reason_hash"] == "b" * 64

    fixed = source + "\n# follow-up revision\n"
    install_source(direct_vm, "hardened_fact_checker_v2", fixed)
    second = request(contract, "hardened_fact_checker_v2", fixed, 0)

    assert json.loads(contract.get_audit(first))["superseded_by"] == "1"
    assert json.loads(contract.get_audit(second))["supersedes_id"] == "0"
