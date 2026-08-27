from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from equivlab.canonicalize import canonical_sha256


ROOT = Path(__file__).parents[2]
CONTRACT_PATH = ROOT / "contracts" / "consensus_safety_registry.py"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class _Decorator:
    def __call__(self, function):
        return function


class _Return:
    def __init__(self, calldata):
        self.calldata = calldata


class _Result:
    pass


class _Contract:
    pass


class FakeRuntime:
    def __init__(self):
        self.web_values: list[object] = []
        self.validator_accepted: bool | None = None

    def get(self, _url: str, **_kwargs):
        if not self.web_values:
            raise RuntimeError("missing web mock")
        value = self.web_values.pop(0)
        if isinstance(value, Exception):
            raise value
        body = value.encode("utf-8") if isinstance(value, str) else value
        return types.SimpleNamespace(body=body)

    def run_nondet_unsafe(self, leader, validator):
        leader_payload = leader()
        self.validator_accepted = bool(validator(_Return(leader_payload)))
        if not self.validator_accepted:
            raise ValueError("validator disagreement")
        return leader_payload


def load_contract_module():
    runtime = FakeRuntime()
    write = _Decorator()
    write.payable = _Decorator()
    public = types.SimpleNamespace(write=write, view=_Decorator())
    vm = types.SimpleNamespace(
        Result=_Result,
        Return=_Return,
        UserError=ValueError,
        run_nondet_unsafe=runtime.run_nondet_unsafe,
    )
    nondet = types.SimpleNamespace(web=types.SimpleNamespace(get=runtime.get))
    gl = types.SimpleNamespace(
        Contract=_Contract,
        message=types.SimpleNamespace(sender_address="0xrequester"),
        message_raw={"datetime": "2026-08-24T12:00:00Z"},
        nondet=nondet,
        public=public,
        vm=vm,
    )
    fake_genlayer = types.ModuleType("genlayer")
    fake_genlayer.gl = gl
    fake_genlayer.DynArray = list
    fake_genlayer.TreeMap = dict
    fake_genlayer.u64 = int
    fake_genlayer.u256 = int
    fake_genlayer.Address = str
    previous_genlayer = sys.modules.get("genlayer")
    sys.modules["genlayer"] = fake_genlayer
    try:
        spec = importlib.util.spec_from_file_location("equivlab_registry_contract_under_test", CONTRACT_PATH)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if previous_genlayer is None:
            sys.modules.pop("genlayer", None)
        else:
            sys.modules["genlayer"] = previous_genlayer

    registry = module.ConsensusSafetyRegistry()
    registry.audits = []
    registry.reports = []
    registry.latest_by_source_identity_policy = {}
    registry.superseded_by = {}
    registry.challenges = []
    registry.challenge_ids_by_audit = {}
    registry.challenge_count_by_audit = {}
    registry.next_challenge_id = 0
    return module, registry, runtime


def fixture_source(name: str) -> str:
    return (ROOT / "fixtures" / name / "contract.py").read_text(encoding="utf-8")


def pinned_url(name: str) -> str:
    return f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/{name}/contract.py"


def arrange_consensus(runtime: FakeRuntime, source: str) -> None:
    runtime.web_values = [source, source]


def request(registry, source: str, name: str, supersedes_id: int | None = None):
    args = (pinned_url(name), canonical_sha256(source), "gl-consensus-baseline-1")
    if supersedes_id is None:
        return registry.request_audit(*args)
    return registry.request_superseding_audit(*args, supersedes_id)


def report(registry, audit_id: int) -> dict[str, object]:
    return json.loads(registry.get_report(audit_id))


def audit(registry, audit_id: int) -> dict[str, object]:
    return json.loads(registry.get_audit(audit_id))


def test_backdoored_tip_jar_records_expected_deterministic_failure() -> None:
    _module, registry, runtime = load_contract_module()
    source = fixture_source("backdoored_tip_jar")
    arrange_consensus(runtime, source)

    audit_id = request(registry, source, "backdoored_tip_jar")

    assert audit_id == 0
    assert report(registry, audit_id)["status"] == "FAIL"
    assert report(registry, audit_id)["failed_rules"] == ["AUTH-01", "VALUE-01"]


def test_schema_only_checker_records_consensus_and_evidence_failures() -> None:
    _module, registry, runtime = load_contract_module()
    source = fixture_source("schema_only_fact_checker")
    arrange_consensus(runtime, source)

    audit_id = request(registry, source, "schema_only_fact_checker")

    assert report(registry, audit_id)["failed_rules"] == ["CONS-01", "EVID-01"]


def test_hardened_revision_can_record_meets_baseline() -> None:
    _module, registry, runtime = load_contract_module()
    source = fixture_source("hardened_fact_checker")
    arrange_consensus(runtime, source)

    audit_id = request(registry, source, "hardened_fact_checker")

    stored = report(registry, audit_id)
    assert stored["status"] == "MEETS_BASELINE"
    assert stored["failed_rules"] == []
    assert stored["warning_rules"] == []
    assert runtime.validator_accepted is True


def test_hash_mismatch_finalizes_unverifiable() -> None:
    _module, registry, runtime = load_contract_module()
    source = fixture_source("hardened_fact_checker")
    runtime.web_values = [source, source]

    audit_id = registry.request_audit(
        pinned_url("hardened_fact_checker"),
        "0" * 64,
        "gl-consensus-baseline-1",
    )

    stored = report(registry, audit_id)
    assert stored["status"] == "UNVERIFIABLE"
    assert stored["severity"] == "CRITICAL"
    assert stored["unverifiable_rules"] == list(_module.RULE_IDS)


def test_fetch_failure_finalizes_unverifiable() -> None:
    _module, registry, runtime = load_contract_module()
    source = fixture_source("hardened_fact_checker")
    runtime.web_values = [RuntimeError("offline"), RuntimeError("offline")]

    audit_id = request(registry, source, "hardened_fact_checker")

    assert report(registry, audit_id)["status"] == "UNVERIFIABLE"


def test_leader_validator_source_disagreement_writes_no_state() -> None:
    _module, registry, runtime = load_contract_module()
    source = fixture_source("hardened_fact_checker")
    runtime.web_values = [source, source + "\n# changed after leader fetch\n"]

    with pytest.raises(ValueError, match="validator disagreement"):
        request(registry, source, "hardened_fact_checker")

    assert registry.count() == 0
    assert registry.audits == []


def test_duplicate_source_policy_audit_is_rejected() -> None:
    _module, registry, runtime = load_contract_module()
    source = fixture_source("hardened_fact_checker")
    arrange_consensus(runtime, source)
    request(registry, source, "hardened_fact_checker")

    with pytest.raises(ValueError, match="duplicate source identity and policy audit"):
        request(registry, source, "hardened_fact_checker")


def test_same_bytes_at_distinct_urls_do_not_preempt_each_other() -> None:
    _module, registry, runtime = load_contract_module()
    source = fixture_source("hardened_fact_checker")
    source_hash = canonical_sha256(source)
    arrange_consensus(runtime, source)
    first = request(registry, source, "mirror_one")
    arrange_consensus(runtime, source)
    second = request(registry, source, "mirror_two")

    assert first == 0 and second == 1
    assert registry.get_latest(pinned_url("mirror_one"), source_hash, "gl-consensus-baseline-1") == "0"
    assert registry.get_latest(pinned_url("mirror_two"), source_hash, "gl-consensus-baseline-1") == "1"


def test_challenges_are_append_only_and_preserve_report() -> None:
    module, registry, runtime = load_contract_module()
    source = fixture_source("hardened_fact_checker")
    arrange_consensus(runtime, source)
    audit_id = request(registry, source, "hardened_fact_checker")
    original_report = registry.get_report(audit_id)
    reason_hash = "a" * 64

    assert registry.challenge(audit_id, reason_hash) == "0"
    module.gl.message.sender_address = "0xsecond-challenger"
    assert registry.challenge(audit_id, "b" * 64) == "1"

    stored_audit = audit(registry, audit_id)
    assert stored_audit["challenged"] is True
    assert stored_audit["challenge_count"] == 2
    assert registry.get_challenge_count(audit_id) == 2
    first = json.loads(registry.get_challenge(0))
    second = json.loads(registry.get_audit_challenge(audit_id, 1))
    assert first == {
        "audit_id": "0",
        "challenged_at": "2026-08-24T12:00:00Z",
        "challenger": "0xrequester",
        "id": "0",
        "reason_hash": reason_hash,
    }
    assert second["challenger"] == "0xsecond-challenger"
    assert second["reason_hash"] == "b" * 64
    assert registry.get_report(audit_id) == original_report


def test_fixed_revision_supersedes_without_erasing_history() -> None:
    _module, registry, runtime = load_contract_module()
    original = fixture_source("hardened_fact_checker")
    fixed = original + "\n# source-pinned follow-up revision\n"
    arrange_consensus(runtime, original)
    first_id = request(registry, original, "hardened_fact_checker")
    arrange_consensus(runtime, fixed)
    second_id = request(registry, fixed, "hardened_fact_checker_v2", supersedes_id=0)

    assert first_id == 0 and second_id == 1
    assert audit(registry, first_id)["superseded_by"] == "1"
    assert audit(registry, second_id)["supersedes_id"] == "0"
    assert json.loads(registry.get_report(first_id))["status"] == "MEETS_BASELINE"
    assert registry.count() == 2


def test_only_original_requester_may_supersede() -> None:
    module, registry, runtime = load_contract_module()
    original = fixture_source("hardened_fact_checker")
    arrange_consensus(runtime, original)
    request(registry, original, "hardened_fact_checker")
    module.gl.message.sender_address = "0xattacker"
    fixed = original + "\n# attacker revision\n"

    with pytest.raises(ValueError, match="only the original requester"):
        request(registry, fixed, "attacker_revision", supersedes_id=0)

    assert audit(registry, 0)["superseded_by"] is None
    assert registry.count() == 1


def test_latest_lookup_and_report_hash_are_stable() -> None:
    module, registry, runtime = load_contract_module()
    source = fixture_source("hardened_fact_checker")
    source_hash = canonical_sha256(source)
    arrange_consensus(runtime, source)
    audit_id = request(registry, source, "hardened_fact_checker")

    stored = report(registry, audit_id)
    claimed = stored.pop("report_sha256")
    assert claimed == module._sha256_text(module._canonical_json(stored))
    assert registry.get_latest(pinned_url("hardened_fact_checker"), source_hash, "gl-consensus-baseline-1") == "0"
    assert registry.get_latest(pinned_url("hardened_fact_checker"), "f" * 64, "gl-consensus-baseline-1") == ""


@pytest.mark.parametrize(
    "source_url",
    [
        f"https://user@raw.githubusercontent.com/equivlab/demo/{COMMIT}/contract.py",
        f"https://raw.githubusercontent.com:443/equivlab/demo/{COMMIT}/contract.py",
        f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/contract.py?raw=1",
        f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/contract.py#fragment",
        f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/%2e%2e/contract.py",
        f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/nested%2fcontract.py",
        "https://raw.githubusercontent.com/equivlab/demo/main/contract.py",
    ],
)
def test_source_url_rejects_noncanonical_or_unpinned_forms(source_url: str) -> None:
    _module, registry, _runtime = load_contract_module()
    with pytest.raises(ValueError, match="source URL"):
        registry.request_audit(source_url, "a" * 64, "gl-consensus-baseline-1")


def _transfer_contract(guard: str) -> str:
    return f'''from genlayer import *

class Vault(gl.Contract):
    owner: Address
    enabled: bool
    paused: bool

    @gl.public.write
    def withdraw(self, recipient: str):
{guard}
        gl.eth_transfer(Address(recipient), self.balance)
'''


@pytest.mark.parametrize(
    "guard",
    [
        "        assert gl.message.sender_address != self.owner",
        "        assert gl.message.sender_address == self.owner or gl.message.sender_address != self.owner",
        "        assert gl.message.sender_address == self.owner or self.enabled",
        "        if gl.message.sender_address == self.owner:\n            raise ValueError('blocked')",
        "        if gl.message.sender_address != self.owner:\n            pass\n        else:\n            raise ValueError('blocked')",
        "        if gl.message.sender_address != self.owner and self.enabled:\n            raise ValueError('blocked')",
        "        if self.enabled:\n            if gl.message.sender_address != self.owner:\n                raise ValueError('blocked')",
        "        if gl.message.sender_address != self.owner:\n            self.log_attempt()\n            raise ValueError('blocked')",
        "        actor = gl.message.sender_address\n        actor = self.owner\n        assert actor == self.owner",
        "        assert self.owner in gl.message.sender_address",
        "        assert gl.message.sender_address == self.owner, self.log_attempt()",
    ],
)
def test_adversarial_authority_guards_fail_closed(guard: str) -> None:
    module, _registry, _runtime = load_contract_module()
    failed = module._deterministic_findings(_transfer_contract(guard), pinned_url("authority_case"))
    assert "AUTH-01" in failed
    assert "VALUE-01" in failed


@pytest.mark.parametrize(
    "guard",
    [
        "        assert gl.message.sender_address == self.owner",
        "        assert gl.message.sender_address == self.owner and self.enabled",
        "        if gl.message.sender_address != self.owner:\n            raise ValueError('unauthorized')",
        "        if gl.message.sender_address != self.owner or self.paused:\n            raise ValueError('blocked')",
        "        if gl.message.sender_address == self.owner:\n            pass\n        else:\n            raise ValueError('unauthorized')",
        "        caller = gl.message.sender_address\n        owner = self.owner\n        assert caller == owner",
        "        assert gl.message.sender_address in self.owners",
    ],
)
def test_valid_authority_guards_are_recognized(guard: str) -> None:
    module, _registry, _runtime = load_contract_module()
    failed = module._deterministic_findings(_transfer_contract(guard), pinned_url("authority_case"))
    assert "AUTH-01" not in failed
    assert "VALUE-01" not in failed


def test_observation_validator_rejects_inconsistent_consensus_fields() -> None:
    module, _registry, _runtime = load_contract_module()
    source_hash = "a" * 64
    source_url = pinned_url("sample")
    valid = module._build_observation(source_url, source_hash, "MEETS_BASELINE", [], [], [])
    assert module._validate_observation(valid, source_hash, source_url) is True

    bad_status = dict(valid)
    bad_status["status"] = "FAIL"
    assert module._validate_observation(bad_status, source_hash, source_url) is False

    bad_severity = dict(valid)
    bad_severity["severity"] = "CRITICAL"
    assert module._validate_observation(bad_severity, source_hash, source_url) is False

    assert module._validate_observation(valid, source_hash, pinned_url("other")) is False
