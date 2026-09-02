"""Deterministic cores for gl-consensus-baseline-3."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .ast_index import AstIndex, FunctionInfo
from .call_paths import CallPathAnalyzer
from .source_identity import validate_source_url


POLICY_ID = "gl-consensus-baseline-3"
IMPLEMENTED_RULES = (
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
)
SEVERITIES = {
    "SRC-01": "CRITICAL",
    "CONS-01": "CRITICAL",
    "RESULT-01": "HIGH",
    "BOUND-01": "HIGH",
    "AUTH-01": "CRITICAL",
    "VALUE-01": "CRITICAL",
    "EVID-01": "HIGH",
    "PROMPT-01": "HIGH",
    "URL-01": "MEDIUM",
    "STATE-01": "HIGH",
    "REPLAY-01": "HIGH",
    "TIME-01": "MEDIUM",
}


@dataclass(frozen=True)
class Evidence:
    line: int
    symbol: str
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {"detail": self.detail, "line": self.line, "symbol": self.symbol}


@dataclass(frozen=True)
class RuleResult:
    rule: str
    status: str
    summary: str
    evidence: tuple[Evidence, ...] = ()

    @property
    def severity(self) -> str:
        return SEVERITIES[self.rule]


def evaluate_src(
    source_url: str,
    expected_sha256: str | None,
    actual_sha256: str,
    source_mode: str = "retrieved",
) -> RuleResult:
    expected = (expected_sha256 or "").lower().removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        return RuleResult("SRC-01", "UNVERIFIABLE", "A valid submitted canonical SHA-256 is required.")
    if expected != actual_sha256:
        return RuleResult("SRC-01", "UNVERIFIABLE", "Retrieved canonical source bytes do not match the submitted SHA-256.")

    try:
        validate_source_url(source_url)
    except ValueError as exc:
        return RuleResult("SRC-01", "FAIL", str(exc))
    if source_mode == "submitted":
        return RuleResult(
            "SRC-01",
            "UNVERIFIABLE",
            "Submitted bytes match the claimed digest, but the source URL-to-bytes binding was not independently retrieved.",
        )
    if source_mode != "retrieved":
        return RuleResult("SRC-01", "UNVERIFIABLE", "Source provenance mode is not recognized by this policy version.")
    return RuleResult("SRC-01", "MEETS_BASELINE", "Source URL and canonical SHA-256 meet the pinned-source rule.")


def evaluate_auth(index: AstIndex) -> RuleResult:
    failures = [path for path in CallPathAnalyzer(index).transfer_paths() if not path.guarded]
    if not failures:
        return RuleResult("AUTH-01", "MEETS_BASELINE", "Every discovered public value-transfer path has a preceding caller-derived authority guard.")
    evidence = tuple(
        Evidence(path.transfer.line, path.root, "Unguarded transfer path: " + " -> ".join(path.functions))
        for path in failures
    )
    return RuleResult("AUTH-01", "FAIL", "A public value-transfer path has no preceding caller-derived authority guard.", evidence)


def _parameter_dependency(dependencies: tuple[str, ...]) -> bool:
    return any(item.startswith("parameter:") for item in dependencies)


def _caller_dependency(dependencies: tuple[str, ...]) -> bool:
    return bool({"sender", "message.value"} & set(dependencies)) or _parameter_dependency(dependencies)


def _reachable_consensus_functions(index: AstIndex) -> list[FunctionInfo]:
    graph = CallPathAnalyzer(index)
    reachable: set[str] = set()
    for root in index.public_write_functions:
        reachable.update(graph.reachable_functions(root.qualname))
    return [index.functions[name] for name in sorted(reachable)]


def evaluate_value(index: AstIndex) -> RuleResult:
    failures: list[Evidence] = []
    for path in CallPathAnalyzer(index).transfer_paths():
        transfer = path.transfer
        amount_deps = set(transfer.amount_dependencies)
        reasons: list[str] = []
        if not transfer.amount:
            reasons.append("transfer amount is not explicit")
        if "message.value" in amount_deps or _parameter_dependency(transfer.amount_dependencies):
            reasons.append("transfer amount depends on caller input")
        if "nondeterministic" in amount_deps or "consensus-result" in amount_deps:
            reasons.append("transfer amount depends directly on nondeterministic output")
        recipient_deps = set(transfer.recipient_dependencies)
        if _caller_dependency(transfer.recipient_dependencies) and not path.guarded:
            reasons.append("unguarded transfer recipient depends on caller input")
        if recipient_deps & {"nondeterministic", "consensus-result", "model-output"}:
            reasons.append("transfer recipient depends directly on nondeterministic output")
        if reasons:
            failures.append(
                Evidence(
                    transfer.line,
                    path.root,
                    "; ".join(reasons) + f" (amount={transfer.amount or '<missing>'}, recipient={transfer.recipient or '<missing>'})",
                )
            )
    if not failures:
        return RuleResult("VALUE-01", "MEETS_BASELINE", "Discovered transfers use deterministic values and no unguarded caller-controlled recipient.")
    return RuleResult("VALUE-01", "FAIL", "A public transfer path lets caller input or nondeterministic output control material value-transfer fields.", tuple(failures))


def evaluate_consensus(index: AstIndex) -> RuleResult:
    if not index.has_recognizable_contract:
        return RuleResult(
            "CONS-01",
            "UNVERIFIABLE",
            "No recognizable GenLayer contract with a gl.Contract base and public entrypoint was found.",
            (Evidence(1, "<module>", "Expected a class inheriting gl.Contract with at least one @gl.public entrypoint."),),
        )
    graph = CallPathAnalyzer(index)
    failures: list[Evidence] = []
    consensus_functions = _reachable_consensus_functions(index)
    consensus_count = 0
    for function in consensus_functions:
        for call in function.consensus_calls:
            consensus_count += 1
            validator = index.resolve_call(function, call.validator_name)
            if validator is None or not graph.reaches_nondeterminism(validator):
                failures.append(
                    Evidence(
                        call.line,
                        function.qualname,
                        f"Validator {call.validator_name or '<missing>'} has no independently reachable nondeterministic evaluation path.",
                    )
                )
    if failures:
        return RuleResult("CONS-01", "FAIL", "At least one validator checks leader output without independently invoking an evaluation path.", tuple(failures))
    if consensus_count == 0:
        return RuleResult(
            "CONS-01",
            "UNVERIFIABLE",
            "A GenLayer contract was found, but no run_nondet_unsafe consensus path is reachable from a public write entrypoint.",
            tuple(
                Evidence(root.line, root.qualname, "Public write entrypoint has no reachable GenLayer consensus call.")
                for root in index.public_write_functions
            ),
        )
    return RuleResult("CONS-01", "MEETS_BASELINE", "Every discovered validator invokes an independently reachable nondeterministic evaluation path.")


def evaluate_result(index: AstIndex) -> RuleResult:
    failures: list[Evidence] = []
    count = 0
    for function in _reachable_consensus_functions(index):
        for call in function.consensus_calls:
            count += 1
            validator_name = index.resolve_call(function, call.validator_name)
            validator = index.functions.get(validator_name or "")
            parameter = validator.parameters[0] if validator and validator.parameters else ""
            if validator is None or not parameter or parameter not in validator.result_guard_parameters:
                failures.append(
                    Evidence(call.line, function.qualname, f"Validator {call.validator_name or '<missing>'} lacks an explicit fail-closed gl.vm.Result/Return type guard.")
                )
    if failures:
        return RuleResult("RESULT-01", "FAIL", "A consensus validator does not explicitly handle non-return result variants.", tuple(failures))
    summary = "Every discovered validator has an explicit fail-closed Result/Return type guard."
    if count == 0:
        summary = "No run_nondet_unsafe consensus call is present in this source."
    return RuleResult("RESULT-01", "MEETS_BASELINE", summary)


def evaluate_bound(index: AstIndex) -> RuleResult:
    failures: list[Evidence] = []
    for function in _reachable_consensus_functions(index):
        for write in function.state_writes:
            if not set(write.dependencies) & {"consensus-result", "model-output"}:
                continue
            if not any(line < write.line for line in function.bounded_guard_lines):
                failures.append(
                    Evidence(write.line, function.qualname, f"Model-derived state write {write.target} has no preceding enum/range guard.")
                )
    if failures:
        return RuleResult("BOUND-01", "FAIL", "A model-derived state field is written without a preceding bounded enum or range check.", tuple(failures))
    return RuleResult("BOUND-01", "MEETS_BASELINE", "Every discovered model-derived state write has a preceding enum or range guard.")


def evaluate_evidence(index: AstIndex) -> RuleResult:
    graph = CallPathAnalyzer(index)
    failures: list[Evidence] = []
    observed = 0
    for function in sorted(index.functions.values(), key=lambda item: item.qualname):
        for call in function.consensus_calls:
            leader = index.resolve_call(function, call.leader_name)
            validator = index.resolve_call(function, call.validator_name)
            if leader is None or not graph.reaches_web_observation(leader):
                continue
            observed += 1
            if validator is None or not graph.reaches_web_observation(validator):
                failures.append(
                    Evidence(call.line, function.qualname, f"Validator {call.validator_name or '<missing>'} does not independently re-observe web evidence.")
                )
    if failures:
        return RuleResult("EVID-01", "FAIL", "Leader-observed web evidence can reach consensus without a validator re-observation path.", tuple(failures))
    summary = "Every web-evidence consensus path includes validator re-observation."
    if observed == 0:
        summary = "No leader web-evidence consensus path is present in this source."
    return RuleResult("EVID-01", "MEETS_BASELINE", summary)


def evaluate_prompt(index: AstIndex) -> RuleResult:
    failures: list[Evidence] = []
    for function in sorted(index.functions.values(), key=lambda item: item.qualname):
        for prompt in function.prompt_calls:
            untrusted = set(prompt.dependencies) & {"web", "nondeterministic"}
            untrusted.update(item for item in prompt.dependencies if item.startswith("parameter:"))
            if untrusted and not prompt.explicitly_framed:
                failures.append(
                    Evidence(prompt.line, function.qualname, "Untrusted prompt data lacks an explicit data-not-instructions framing marker.")
                )
    if failures:
        return RuleResult("PROMPT-01", "FAIL", "Untrusted content enters a model prompt without explicit evidence framing.", tuple(failures))
    return RuleResult("PROMPT-01", "MEETS_BASELINE", "Discovered untrusted prompt inputs use an explicit evidence-framing marker.")


def _scope_reaches_web(index: AstIndex, root_name: str, graph: CallPathAnalyzer) -> bool:
    if graph.reaches_web_observation(root_name):
        return True
    prefix = root_name + ".<locals>."
    return any(name.startswith(prefix) and graph.reaches_web_observation(name) for name in index.functions)


def evaluate_url(index: AstIndex) -> RuleResult:
    graph = CallPathAnalyzer(index)
    failures: list[Evidence] = []
    for function in index.public_write_functions:
        if not _scope_reaches_web(index, function.qualname, graph):
            continue
        url_parameters = [name for name in function.parameters if "url" in name.lower() or "source" in name.lower()]
        if not url_parameters:
            continue
        missing: list[str] = []
        if not function.url_scheme_guard_lines:
            missing.append("HTTPS scheme")
        if not function.url_host_guard_lines:
            missing.append("approved host")
        if not function.url_length_guard_lines:
            missing.append("bounded length")
        plural = any(name.lower().endswith("s") for name in url_parameters)
        if plural and not function.url_duplicate_guard_lines:
            missing.append("duplicate policy")
        if missing:
            failures.append(
                Evidence(function.line, function.qualname, "Missing URL checks: " + ", ".join(missing) + ".")
            )
    if failures:
        return RuleResult("URL-01", "FAIL", "A public web-observation path lacks required URL constraints.", tuple(failures))
    return RuleResult("URL-01", "MEETS_BASELINE", "Discovered public web-observation paths enforce HTTPS, host, length, and applicable duplicate constraints.")


def evaluate_state(index: AstIndex) -> RuleResult:
    graph = CallPathAnalyzer(index)
    failures: list[Evidence] = []
    for failure in graph.state_order_failures():
        failures.append(
            Evidence(
                failure.write.line,
                failure.function,
                f"State write {failure.write.target} is reachable before consensus completes from {failure.root}.",
            )
        )
    for function in _reachable_consensus_functions(index):
        for call in function.consensus_calls:
            for callback_name in (call.leader_name, call.validator_name):
                callback = index.resolve_call(function, callback_name)
                if callback is None:
                    continue
                for reachable in graph.reachable_functions(callback):
                    for write in index.functions[reachable].state_writes:
                        failures.append(
                            Evidence(write.line, reachable, f"Consensus callback mutates {write.target}.")
                        )
    if failures:
        return RuleResult("STATE-01", "FAIL", "Final-looking state can be mutated before consensus success or inside a consensus callback.", tuple(failures))
    return RuleResult("STATE-01", "MEETS_BASELINE", "Discovered consensus paths mutate state only after run_nondet_unsafe returns.")


def _path_has_ordered_fact(index: AstIndex, path: object, attribute: str) -> bool:
    functions = path.functions
    for offset, function_name in enumerate(functions):
        info = index.functions[function_name]
        cutoff = path.transfer.line if offset == len(functions) - 1 else path.call_lines[offset]
        if any(line < cutoff for line in getattr(info, attribute)):
            return True
    return False


def evaluate_replay(index: AstIndex) -> RuleResult:
    failures: list[Evidence] = []
    for path in CallPathAnalyzer(index).transfer_paths():
        if "balance" in path.transfer.amount.lower():
            continue
        has_guard = _path_has_ordered_fact(index, path, "replay_guard_lines")
        has_effect = _path_has_ordered_fact(index, path, "terminal_write_lines")
        if not has_guard or not has_effect:
            missing = []
            if not has_guard:
                missing.append("terminal replay guard")
            if not has_effect:
                missing.append("terminal state write before transfer")
            failures.append(Evidence(path.transfer.line, path.root, "Missing " + " and ".join(missing) + "."))
    if failures:
        return RuleResult("REPLAY-01", "FAIL", "A repeatable value-settlement path lacks an explicit checks-effects-interactions replay guard.", tuple(failures))
    return RuleResult("REPLAY-01", "MEETS_BASELINE", "Discovered repeatable settlements have a terminal guard and terminal state write before transfer.")


def evaluate_time(index: AstIndex) -> RuleResult:
    failures: list[Evidence] = []
    markers = ("time", "timestamp", "created_at", "updated_at")
    public_reachable: set[str] = set()
    graph = CallPathAnalyzer(index)
    for root in index.public_write_functions:
        public_reachable.update(graph.reachable_functions(root.qualname))
    for function_name in sorted(public_reachable):
        function = index.functions[function_name]
        for write in function.state_writes:
            if not any(marker in write.target.lower() for marker in markers):
                continue
            if any(dependency.startswith("parameter:") for dependency in write.dependencies):
                failures.append(
                    Evidence(write.line, function.qualname, f"Authoritative time field {write.target} depends on caller input.")
                )
    if failures:
        return RuleResult("TIME-01", "FAIL", "A caller-supplied value is stored as authoritative time.", tuple(failures))
    return RuleResult("TIME-01", "MEETS_BASELINE", "Discovered authoritative time fields do not depend on public method parameters.")


def evaluate_ast_rules(index: AstIndex) -> list[RuleResult]:
    return sorted(
        [
            evaluate_auth(index),
            evaluate_bound(index),
            evaluate_consensus(index),
            evaluate_evidence(index),
            evaluate_prompt(index),
            evaluate_replay(index),
            evaluate_result(index),
            evaluate_state(index),
            evaluate_time(index),
            evaluate_url(index),
            evaluate_value(index),
        ],
        key=lambda item: item.rule,
    )
