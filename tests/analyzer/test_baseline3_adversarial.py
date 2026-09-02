from __future__ import annotations

import pytest

from equivlab.ast_index import AstIndex
from equivlab.canonicalize import canonical_sha256
from equivlab.report import analyze_source
from equivlab.rules import evaluate_bound, evaluate_replay, evaluate_result, evaluate_state, evaluate_url


COMMIT = "0123456789abcdef0123456789abcdef01234567"
SOURCE_URL = f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/contract.py"


def _consensus_contract(validator_body: str, *, before_result: str = "", after_result: str = "") -> str:
    return f'''from genlayer import *
class Probe(gl.Contract):
    status: str
    @gl.public.write
    def decide(self):
        def evaluate():
            return gl.nondet.exec_prompt("constant")
        def leader():
            return evaluate()
        def validator(result: gl.vm.Result):
{validator_body}
{before_result}        decision = gl.vm.run_nondet_unsafe(leader, validator)
{after_result}'''


@pytest.mark.parametrize(
    "validator_body",
    [
        "            if isinstance(result, gl.vm.Return):\n                return False\n            return evaluate() == result.calldata",
        "            if not isinstance(result, gl.vm.Return):\n                if self.enabled:\n                    return False\n            return evaluate() == result.calldata",
        "            if False:\n                if not isinstance(result, gl.vm.Return):\n                    return False\n            return evaluate() == result.calldata",
    ],
)
def test_result_guard_rejects_inverted_nested_and_unreachable_checks(validator_body: str) -> None:
    result = evaluate_result(AstIndex.build(_consensus_contract(validator_body)))
    assert result.status == "FAIL"


def test_result_guard_accepts_rejecting_else_for_non_return_variant() -> None:
    source = _consensus_contract(
        "            if isinstance(result, gl.vm.Return):\n                return evaluate() == result.calldata\n            else:\n                return False"
    )
    assert evaluate_result(AstIndex.build(source)).status == "MEETS_BASELINE"


@pytest.mark.parametrize(
    "guard",
    [
        "        if status in ('YES', 'NO'):\n            raise ValueError('inverted')",
        "        if self.enabled:\n            if status not in ('YES', 'NO'):\n                raise ValueError('optional')",
    ],
)
def test_bound_guard_rejects_inverted_or_non_dominating_checks(guard: str) -> None:
    source = _consensus_contract(
        "            if not isinstance(result, gl.vm.Return):\n                return False\n            return evaluate() == result.calldata",
        after_result=f"        status = str(decision)\n{guard}\n        self.status = status\n",
    )
    assert evaluate_bound(AstIndex.build(source)).status == "FAIL"


def test_bound_guard_accepts_allowed_branch_with_rejecting_else() -> None:
    source = _consensus_contract(
        "            if not isinstance(result, gl.vm.Return):\n                return False\n            return evaluate() == result.calldata",
        after_result="""        status = str(decision)
        if status in ('YES', 'NO'):
            pass
        else:
            raise ValueError('invalid')
        self.status = status
""",
    )
    assert evaluate_bound(AstIndex.build(source)).status == "MEETS_BASELINE"


def _url_contract(scheme_guard: str) -> str:
    return f'''from genlayer import *
class Fetcher(gl.Contract):
    @gl.public.write
    def fetch(self, url: str):
{scheme_guard}
        if len(url) > 500:
            raise ValueError("long")
        def evaluate():
            return gl.nondet.web.render(url, mode="text")
        def leader():
            return evaluate()
        def validator(result: gl.vm.Result):
            if not isinstance(result, gl.vm.Return):
                return False
            return evaluate() == result.calldata
        gl.vm.run_nondet_unsafe(leader, validator)
'''


@pytest.mark.parametrize(
    "guard",
    [
        "        if url.startswith('https://raw.githubusercontent.com/'):\n            raise ValueError('inverted')",
        "        if self.enabled:\n            if not url.startswith('https://raw.githubusercontent.com/'):\n                raise ValueError('optional')",
        "        if False:\n            if not url.startswith('https://raw.githubusercontent.com/'):\n                raise ValueError('dead')",
    ],
)
def test_url_guard_rejects_inverted_and_non_dominating_checks(guard: str) -> None:
    assert evaluate_url(AstIndex.build(_url_contract(guard))).status == "FAIL"


def _settlement(guard: str) -> str:
    return f'''from genlayer import *
class Settlement(gl.Contract):
    settled: bool
    recipient: Address
    payout: u256
    @gl.public.write
    def settle(self):
{guard}
        self.settled = True
        gl.eth_transfer(self.recipient, self.payout)
'''


def test_replay_guard_rejects_inverted_terminal_check() -> None:
    source = _settlement("        if not self.settled:\n            raise ValueError('inverted')")
    assert evaluate_replay(AstIndex.build(source)).status == "FAIL"


def test_replay_guard_accepts_terminal_true_rejection() -> None:
    source = _settlement("        if self.settled:\n            raise ValueError('already settled')")
    assert evaluate_replay(AstIndex.build(source)).status == "MEETS_BASELINE"


def test_state_rule_follows_helper_consensus_path() -> None:
    unsafe = '''from genlayer import *
class Decision(gl.Contract):
    status: str
    def _prepare(self):
        self.status = "PENDING"
    def _decide(self):
        def evaluate(): return gl.nondet.exec_prompt("constant")
        def leader(): return evaluate()
        def validator(result):
            if not isinstance(result, gl.vm.Return): return False
            return evaluate() == result.calldata
        return gl.vm.run_nondet_unsafe(leader, validator)
    @gl.public.write
    def decide(self):
        self._prepare()
        self._decide()
'''
    safe = unsafe.replace("        self._prepare()\n        self._decide()", "        self._decide()\n        self._prepare()")
    assert evaluate_state(AstIndex.build(unsafe)).status == "FAIL"
    assert evaluate_state(AstIndex.build(safe)).status == "MEETS_BASELINE"


def test_call_path_budget_returns_unverifiable_instead_of_exhausting_service() -> None:
    methods: list[str] = []
    layers = 13
    for layer in range(layers):
        next_layer = layer + 1
        methods.append(f"    def a{layer}(self):\n        self.a{next_layer}()\n        self.b{next_layer}()")
        methods.append(f"    def b{layer}(self):\n        self.a{next_layer}()\n        self.b{next_layer}()")
    methods.append(f"    def a{layers}(self):\n        gl.eth_transfer(self.recipient, self.balance)")
    methods.append(f"    def b{layers}(self):\n        gl.eth_transfer(self.recipient, self.balance)")
    source = ("from genlayer import *\nclass Graph(gl.Contract):\n    recipient: Address\n" + "\n".join(methods)
              + "\n    @gl.public.write\n    def run(self):\n        self.a0()\n")
    report = analyze_source(source, SOURCE_URL, canonical_sha256(source))
    assert report["status"] == "UNVERIFIABLE"
    assert "deterministic path budget" in str(report["findings"])


def test_dependency_dag_is_memoized_with_bounded_work() -> None:
    assignments = ["        value0 = gl.nondet.exec_prompt('constant')"]
    for index in range(1, 24):
        assignments.append(f"        value{index} = value{index - 1} + value{index - 1}")
    source = """from genlayer import *
class DependencyGraph(gl.Contract):
    status: str
    @gl.public.write
    def run(self):
""" + "\n".join(assignments) + "\n        self.status = value23\n"
    index = AstIndex.build(source)
    assert index.analysis_metrics["dependency_steps"] < 10_000


@pytest.mark.parametrize(
    "url",
    [
        f"https://user@raw.githubusercontent.com/equivlab/demo/{COMMIT}/contract.py",
        f"https://raw.githubusercontent.com:443/equivlab/demo/{COMMIT}/contract.py",
        f"https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/%2e%2e/contract.py",
        f" https://raw.githubusercontent.com/equivlab/demo/{COMMIT}/contract.py ",
    ],
)
def test_analyzer_source_rule_uses_canonical_url_policy(url: str) -> None:
    source = "from genlayer import *\n"
    report = analyze_source(source, url, canonical_sha256(source))
    assert "SRC-01" in report["failed_rules"]


def test_submitted_provenance_is_hashed_and_not_source_authenticated() -> None:
    source = _settlement("        if self.settled:\n            raise ValueError('already settled')")
    digest = canonical_sha256(source)
    retrieved = analyze_source(source, SOURCE_URL, digest, source_mode="retrieved")
    submitted = analyze_source(source, SOURCE_URL, digest, source_mode="submitted")
    assert retrieved["source"]["mode"] == "retrieved"
    assert submitted["source"]["mode"] == "submitted"
    assert retrieved["report_sha256"] != submitted["report_sha256"]
    assert "SRC-01" in submitted["unverifiable_rules"]
