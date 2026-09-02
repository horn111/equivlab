"""Deterministic AST symbol and security-relevant fact index."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Callable, Iterable


MAX_AST_NODES = 20_000
MAX_DEPENDENCY_STEPS = 100_000


class AnalysisLimitExceeded(ValueError):
    """Raised when deterministic static-analysis work exceeds policy limits."""


class _AnalysisBudget:
    def __init__(self, limit: int, label: str):
        self.remaining = limit
        self.label = label

    def consume(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise AnalysisLimitExceeded(f"{self.label} exceeded the deterministic analysis budget")


def dotted_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def rendered(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


@dataclass(frozen=True, order=True)
class CallSite:
    line: int
    name: str


@dataclass(frozen=True, order=True)
class AuthorityGuard:
    line: int
    expression: str


@dataclass(frozen=True, order=True)
class TransferSite:
    line: int
    call_name: str
    recipient: str
    amount: str
    recipient_dependencies: tuple[str, ...]
    amount_dependencies: tuple[str, ...]


@dataclass(frozen=True, order=True)
class ConsensusSite:
    line: int
    leader_name: str
    validator_name: str


@dataclass(frozen=True, order=True)
class StateWrite:
    line: int
    target: str
    value: str
    dependencies: tuple[str, ...]


@dataclass(frozen=True, order=True)
class PromptSite:
    line: int
    prompt: str
    dependencies: tuple[str, ...]
    explicitly_framed: bool


@dataclass
class FunctionInfo:
    qualname: str
    name: str
    class_name: str | None
    parent_qualname: str | None
    line: int
    decorators: tuple[str, ...]
    parameters: tuple[str, ...]
    public_kind: str | None
    calls: list[CallSite] = field(default_factory=list)
    authority_guards: list[AuthorityGuard] = field(default_factory=list)
    transfers: list[TransferSite] = field(default_factory=list)
    consensus_calls: list[ConsensusSite] = field(default_factory=list)
    nondeterministic_lines: list[int] = field(default_factory=list)
    web_observation_lines: list[int] = field(default_factory=list)
    prompt_calls: list[PromptSite] = field(default_factory=list)
    result_guard_parameters: list[str] = field(default_factory=list)
    bounded_guard_lines: list[int] = field(default_factory=list)
    url_scheme_guard_lines: list[int] = field(default_factory=list)
    url_host_guard_lines: list[int] = field(default_factory=list)
    url_length_guard_lines: list[int] = field(default_factory=list)
    url_duplicate_guard_lines: list[int] = field(default_factory=list)
    replay_guard_lines: list[int] = field(default_factory=list)
    terminal_write_lines: list[int] = field(default_factory=list)
    state_writes: list[StateWrite] = field(default_factory=list)
    state_write_lines: list[int] = field(default_factory=list)
    sender_reference_lines: list[int] = field(default_factory=list)


class _DependencyResolver:
    def __init__(
        self,
        parameters: Iterable[str],
        assignments: dict[str, list[ast.AST]],
        budget: _AnalysisBudget,
    ):
        self.parameters = set(parameters)
        self.assignments = assignments
        self.budget = budget
        self._assignment_cache: dict[tuple[str, int, int], tuple[ast.AST, ...]] = {}
        self._dependency_cache: dict[tuple[int, frozenset[str]], frozenset[str]] = {}

    def _assignments_before(self, name: str, node: ast.AST) -> list[ast.AST]:
        use_line = getattr(node, "lineno", 0)
        use_column = getattr(node, "col_offset", 0)
        key = (name, use_line, use_column)
        cached = self._assignment_cache.get(key)
        if cached is None:
            cached = tuple(
                value
                for value in self.assignments.get(name, [])
                if (getattr(value, "lineno", 0), getattr(value, "col_offset", 0)) < (use_line, use_column)
            )
            self._assignment_cache[key] = cached
        return list(cached)

    def dependencies(self, node: ast.AST | None, seen: frozenset[str] = frozenset()) -> set[str]:
        if node is None:
            return set()
        key = (id(node), seen)
        cached = self._dependency_cache.get(key)
        if cached is not None:
            return set(cached)
        self.budget.consume()
        name = dotted_name(node)
        if name == "gl.message.sender_address" or name.startswith("gl.message.sender_address."):
            result = {"sender"}
            self._dependency_cache[key] = frozenset(result)
            return result
        if name == "gl.message.value" or name.startswith("gl.message.value."):
            result = {"message.value"}
            self._dependency_cache[key] = frozenset(result)
            return result
        if name == "gl.message_raw" or name.startswith("gl.message_raw"):
            result = {"node-time"}
            self._dependency_cache[key] = frozenset(result)
            return result
        if name.startswith("self."):
            result = {"state"}
            self._dependency_cache[key] = frozenset(result)
            return result
        if isinstance(node, ast.Name):
            if node.id in self.parameters:
                result = {f"parameter:{node.id}"}
                self._dependency_cache[key] = frozenset(result)
                return result
            assignments = self._assignments_before(node.id, node)
            if assignments and node.id not in seen:
                result: set[str] = set()
                for assignment in assignments:
                    result.update(self.dependencies(assignment, seen | {node.id}))
                self._dependency_cache[key] = frozenset(result)
                return result
            self._dependency_cache[key] = frozenset()
            return set()
        if isinstance(node, ast.Call) and dotted_name(node.func) == "gl.vm.run_nondet_unsafe":
            result = {"consensus-result"}
            self._dependency_cache[key] = frozenset(result)
            return result
        if isinstance(node, ast.Call) and dotted_name(node.func).startswith("gl.nondet.web."):
            result = {"nondeterministic", "web"}
            self._dependency_cache[key] = frozenset(result)
            return result
        if isinstance(node, ast.Call) and dotted_name(node.func).startswith("gl.nondet."):
            result = {"model-output", "nondeterministic"}
            self._dependency_cache[key] = frozenset(result)
            return result

        result: set[str] = set()
        for child in ast.iter_child_nodes(node):
            result.update(self.dependencies(child, seen))
        self._dependency_cache[key] = frozenset(result)
        return result

    def source(self, node: ast.AST | None, seen: frozenset[str] = frozenset()) -> str:
        if isinstance(node, ast.Name) and node.id not in seen:
            assignments = self._assignments_before(node.id, node)
            if assignments:
                return self.source(assignments[-1], seen | {node.id})
        return rendered(node)


def _statement_always_blocks(statement: ast.stmt) -> bool:
    """Return whether reaching *statement* cannot continue to its successor.

    This deliberately recognizes only a small, deterministic subset of Python
    control flow.  Merely containing a nested ``raise`` is not enough: an
    authority check must fail closed on every path through the rejecting suite.
    """

    if isinstance(statement, (ast.Raise, ast.Return)):
        return True
    if isinstance(statement, ast.If):
        return bool(statement.orelse) and _suite_always_blocks(statement.body) and _suite_always_blocks(statement.orelse)
    return False


def _suite_always_blocks(statements: list[ast.stmt]) -> bool:
    # Accept only an immediate terminal statement.  Treating a later raise as a
    # guard would bless calls or transfers that execute first in the rejecting
    # branch.
    return bool(statements) and _statement_always_blocks(statements[0])


def _suite_rejects_result(statements: list[ast.stmt]) -> bool:
    if not statements:
        return False
    first = statements[0]
    if isinstance(first, ast.Raise):
        return True
    return isinstance(first, ast.Return) and isinstance(first.value, ast.Constant) and first.value.value is False


def _boolean_outcome_entails(
    node: ast.BoolOp,
    truth: bool,
    predicate: Callable[[ast.AST, bool], bool],
) -> bool:
    outcomes = [predicate(value, truth) for value in node.values]
    if isinstance(node.op, ast.And):
        return any(outcomes) if truth else all(outcomes)
    return all(outcomes) if truth else any(outcomes)


def _condition_entails_invalid_result(node: ast.AST, truth: bool, parameter: str) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_entails_invalid_result(node.operand, not truth, parameter)
    if isinstance(node, ast.BoolOp):
        return _boolean_outcome_entails(
            node,
            truth,
            lambda value, outcome: _condition_entails_invalid_result(value, outcome, parameter),
        )
    if not isinstance(node, ast.Call) or dotted_name(node.func) != "isinstance" or len(node.args) < 2:
        return False
    return rendered(node.args[0]) == parameter and rendered(node.args[1]) == "gl.vm.Return" and not truth


def _is_result_guard(node: ast.If, parameter: str) -> bool:
    return (
        _suite_rejects_result(node.body) and _condition_entails_invalid_result(node.test, True, parameter)
    ) or (
        _suite_rejects_result(node.orelse) and _condition_entails_invalid_result(node.test, False, parameter)
    )


def _condition_entails_bounded_rejection(node: ast.AST, truth: bool, resolver: _DependencyResolver) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_entails_bounded_rejection(node.operand, not truth, resolver)
    if isinstance(node, ast.BoolOp):
        return _boolean_outcome_entails(
            node,
            truth,
            lambda value, outcome: _condition_entails_bounded_rejection(value, outcome, resolver),
        )
    if not isinstance(node, ast.Compare) or not (resolver.dependencies(node) & {"consensus-result", "model-output"}):
        return False
    if len(node.ops) != 1:
        return False
    operator = node.ops[0]
    if isinstance(operator, (ast.NotIn, ast.NotEq)):
        return truth
    if isinstance(operator, (ast.In, ast.Eq)):
        return not truth
    return isinstance(operator, (ast.Lt, ast.LtE, ast.Gt, ast.GtE))


def _is_bounded_guard(node: ast.If, resolver: _DependencyResolver) -> bool:
    return (
        _suite_always_blocks(node.body) and _condition_entails_bounded_rejection(node.test, True, resolver)
    ) or (
        _suite_always_blocks(node.orelse) and _condition_entails_bounded_rejection(node.test, False, resolver)
    )


def _condition_entails_terminal_state(node: ast.AST, truth: bool, resolver: _DependencyResolver) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_entails_terminal_state(node.operand, not truth, resolver)
    if isinstance(node, ast.BoolOp):
        return _boolean_outcome_entails(
            node,
            truth,
            lambda value, outcome: _condition_entails_terminal_state(value, outcome, resolver),
        )
    expression = rendered(node).lower()
    if "state" not in resolver.dependencies(node) or not any(marker in expression for marker in _TERMINAL_MARKERS):
        return False
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return truth
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        if isinstance(node.ops[0], (ast.Eq, ast.Is, ast.In)):
            return truth
        if isinstance(node.ops[0], (ast.NotEq, ast.IsNot, ast.NotIn)):
            return not truth
    return False


def _is_replay_guard(node: ast.If, resolver: _DependencyResolver) -> bool:
    return (
        _suite_always_blocks(node.body) and _condition_entails_terminal_state(node.test, True, resolver)
    ) or (
        _suite_always_blocks(node.orelse) and _condition_entails_terminal_state(node.test, False, resolver)
    )


def _named_subject(node: ast.AST, subjects: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in subjects


def _url_prefix_call(node: ast.AST, subjects: set[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "startswith"
        and _named_subject(node.func.value, subjects)
        and bool(node.args)
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and node.args[0].value == "https://raw.githubusercontent.com/"
    )


def _len_subject(node: ast.AST, subjects: set[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and dotted_name(node.func) == "len"
        and len(node.args) == 1
        and _named_subject(node.args[0], subjects)
    )


def _len_set_subject(node: ast.AST, subjects: set[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and dotted_name(node.func) == "len"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Call)
        and dotted_name(node.args[0].func) == "set"
        and len(node.args[0].args) == 1
        and _named_subject(node.args[0].args[0], subjects)
    )


def _condition_entails_url_invalid(node: ast.AST, truth: bool, kind: str, subjects: set[str]) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_entails_url_invalid(node.operand, not truth, kind, subjects)
    if isinstance(node, ast.BoolOp):
        return _boolean_outcome_entails(
            node,
            truth,
            lambda value, outcome: _condition_entails_url_invalid(value, outcome, kind, subjects),
        )
    if kind in {"scheme", "host"}:
        return _url_prefix_call(node, subjects) and not truth
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return False
    left, right, operator = node.left, node.comparators[0], node.ops[0]
    if kind == "length":
        if _len_subject(left, subjects) and isinstance(right, ast.Constant) and isinstance(right.value, int):
            if isinstance(operator, (ast.Gt, ast.GtE)):
                return truth
            if isinstance(operator, (ast.Lt, ast.LtE)):
                return not truth
        if isinstance(left, ast.Constant) and isinstance(left.value, int) and _len_subject(right, subjects):
            if isinstance(operator, (ast.Lt, ast.LtE)):
                return truth
            if isinstance(operator, (ast.Gt, ast.GtE)):
                return not truth
        return False
    if kind == "duplicate":
        pair = (_len_set_subject(left, subjects) and _len_subject(right, subjects)) or (
            _len_subject(left, subjects) and _len_set_subject(right, subjects)
        )
        if not pair:
            return False
        if isinstance(operator, (ast.NotEq, ast.IsNot)):
            return truth
        if isinstance(operator, (ast.Eq, ast.Is)):
            return not truth
    return False


def _is_url_guard(node: ast.If, kind: str, subjects: set[str]) -> bool:
    return (
        _suite_always_blocks(node.body) and _condition_entails_url_invalid(node.test, True, kind, subjects)
    ) or (
        _suite_always_blocks(node.orelse) and _condition_entails_url_invalid(node.test, False, kind, subjects)
    )


def _sender_state_orientation(left: ast.AST, right: ast.AST, resolver: _DependencyResolver) -> str | None:
    left_dependencies = resolver.dependencies(left)
    right_dependencies = resolver.dependencies(right)
    if left_dependencies == {"sender"} and right_dependencies == {"state"}:
        return "sender-left"
    if left_dependencies == {"state"} and right_dependencies == {"sender"}:
        return "sender-right"
    return None


def _condition_entails_authority(node: ast.AST, truth: bool, resolver: _DependencyResolver) -> bool:
    """Conservatively prove that a condition outcome authorizes the sender.

    Equality (or membership) is the allow condition.  Boolean combinations are
    accepted only where the requested truth value forces an authority-bearing
    operand to have the required value.  This rejects tautologies and partial
    guards such as ``sender == owner or emergency``.
    """

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_entails_authority(node.operand, not truth, resolver)

    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And) and truth:
            return any(_condition_entails_authority(value, True, resolver) for value in node.values)
        if isinstance(node.op, ast.Or) and not truth:
            return any(_condition_entails_authority(value, False, resolver) for value in node.values)
        return False

    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return False
    orientation = _sender_state_orientation(node.left, node.comparators[0], resolver)
    if orientation is None:
        return False

    operator = node.ops[0]
    if isinstance(operator, ast.Eq):
        return truth
    if isinstance(operator, ast.NotEq):
        return not truth
    if isinstance(operator, ast.In) and orientation == "sender-left":
        return truth
    if isinstance(operator, ast.NotIn) and orientation == "sender-left":
        return not truth
    return False


def _is_authority_guard(node: ast.If, resolver: _DependencyResolver) -> bool:
    body_rejects = _suite_always_blocks(node.body)
    else_rejects = bool(node.orelse) and _suite_always_blocks(node.orelse)
    return (body_rejects and _condition_entails_authority(node.test, False, resolver)) or (
        else_rejects and _condition_entails_authority(node.test, True, resolver)
    )


_TERMINAL_MARKERS = ("settled", "withdrawn", "paid", "claimed", "completed", "processed", "finalized")
_PROMPT_MARKERS = ("UNTRUSTED EVIDENCE", "UNTRUSTED_EVIDENCE", "EVIDENCE (DATA ONLY)", "DATA, NOT INSTRUCTIONS")


class _AssignmentCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.assignments: dict[str, list[ast.AST]] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments.setdefault(target.id, []).append(node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.assignments.setdefault(node.target.id, []).append(node.value)
        self.generic_visit(node)


class _FunctionScanner(ast.NodeVisitor):
    def __init__(
        self,
        info: FunctionInfo,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        dependency_budget: _AnalysisBudget,
    ):
        self.info = info
        self.top_level_statement_ids = {id(statement) for statement in node.body}
        url_parameters = {name for name in info.parameters if "url" in name.lower() or "source" in name.lower()}
        self.url_guard_subjects: dict[int, set[str]] = {
            id(statement): set(url_parameters) for statement in node.body if isinstance(statement, ast.If)
        }
        for statement in node.body:
            if not isinstance(statement, (ast.For, ast.AsyncFor)):
                continue
            if not isinstance(statement.target, ast.Name) or not isinstance(statement.iter, ast.Name):
                continue
            if statement.iter.id not in url_parameters:
                continue
            subjects = {statement.target.id}
            for child in statement.body:
                if isinstance(child, ast.If):
                    self.url_guard_subjects[id(child)] = subjects
        collector = _AssignmentCollector()
        for statement in node.body:
            collector.visit(statement)
        self.resolver = _DependencyResolver(info.parameters, collector.assignments, dependency_budget)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Name(self, node: ast.Name) -> None:
        if self.resolver.dependencies(node) == {"sender"}:
            self.info.sender_reference_lines.append(node.lineno)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if dotted_name(node) == "gl.message.sender_address":
            self.info.sender_reference_lines.append(node.lineno)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        state_targets = [dotted_name(target) for target in node.targets if dotted_name(target).startswith("self.")]
        if state_targets:
            self.info.state_write_lines.append(node.lineno)
            dependencies = tuple(sorted(self.resolver.dependencies(node.value)))
            for target in state_targets:
                self.info.state_writes.append(StateWrite(node.lineno, target, rendered(node.value), dependencies))
                if any(marker in target.lower() for marker in _TERMINAL_MARKERS):
                    self.info.terminal_write_lines.append(node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if dotted_name(node.target).startswith("self."):
            self.info.state_write_lines.append(node.lineno)
            dependencies = tuple(sorted(self.resolver.dependencies(node.value)))
            target = dotted_name(node.target)
            self.info.state_writes.append(StateWrite(node.lineno, target, rendered(node.value), dependencies))
            if any(marker in target.lower() for marker in _TERMINAL_MARKERS):
                self.info.terminal_write_lines.append(node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if dotted_name(node.target).startswith("self."):
            self.info.state_write_lines.append(node.lineno)
            target = dotted_name(node.target)
            dependencies = tuple(sorted(self.resolver.dependencies(node.value) | {"state"}))
            self.info.state_writes.append(StateWrite(node.lineno, target, rendered(node.value), dependencies))
            if any(marker in target.lower() for marker in _TERMINAL_MARKERS):
                self.info.terminal_write_lines.append(node.lineno)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if id(node) in self.top_level_statement_ids and _is_authority_guard(node, self.resolver):
            self.info.authority_guards.append(AuthorityGuard(node.lineno, rendered(node.test)))
        if id(node) in self.top_level_statement_ids:
            for parameter in self.info.parameters:
                if _is_result_guard(node, parameter):
                    self.info.result_guard_parameters.append(parameter)
            if _is_bounded_guard(node, self.resolver):
                self.info.bounded_guard_lines.append(node.lineno)
            if _is_replay_guard(node, self.resolver):
                self.info.replay_guard_lines.append(node.lineno)
        subjects = self.url_guard_subjects.get(id(node))
        if subjects:
            if _is_url_guard(node, "scheme", subjects):
                self.info.url_scheme_guard_lines.append(node.lineno)
            if _is_url_guard(node, "host", subjects):
                self.info.url_host_guard_lines.append(node.lineno)
            if _is_url_guard(node, "length", subjects):
                self.info.url_length_guard_lines.append(node.lineno)
            if _is_url_guard(node, "duplicate", subjects):
                self.info.url_duplicate_guard_lines.append(node.lineno)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        message_has_effects = node.msg is not None and any(
            isinstance(item, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr)) for item in ast.walk(node.msg)
        )
        if (
            id(node) in self.top_level_statement_ids
            and not message_has_effects
            and _condition_entails_authority(node.test, True, self.resolver)
        ):
            self.info.authority_guards.append(AuthorityGuard(node.lineno, rendered(node.test)))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = dotted_name(node.func)
        self.info.calls.append(CallSite(node.lineno, call_name))
        if call_name.startswith("gl.nondet."):
            self.info.nondeterministic_lines.append(node.lineno)
        if call_name.startswith("gl.nondet.web."):
            self.info.web_observation_lines.append(node.lineno)
        if call_name == "gl.nondet.exec_prompt":
            prompt_node = node.args[0] if node.args else None
            prompt_text = self.resolver.source(prompt_node)
            self.info.prompt_calls.append(
                PromptSite(
                    node.lineno,
                    prompt_text,
                    tuple(sorted(self.resolver.dependencies(prompt_node))),
                    any(marker in prompt_text.upper() for marker in _PROMPT_MARKERS),
                )
            )
        if call_name == "gl.vm.run_nondet_unsafe":
            leader = rendered(node.args[0]) if len(node.args) >= 1 else ""
            validator = rendered(node.args[1]) if len(node.args) >= 2 else ""
            self.info.consensus_calls.append(ConsensusSite(node.lineno, leader, validator))
        is_emit_transfer = call_name == "emit_transfer" or call_name.endswith(".emit_transfer")
        if call_name == "gl.eth_transfer" or is_emit_transfer:
            recipient_node: ast.AST | None = node.args[0] if node.args else None
            amount_node: ast.AST | None = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg in {"to", "recipient", "address"}:
                    recipient_node = keyword.value
                elif keyword.arg in {"value", "amount"}:
                    amount_node = keyword.value
            if is_emit_transfer and isinstance(node.func, ast.Attribute):
                account_expr = node.func.value
                if isinstance(account_expr, ast.Call) and dotted_name(account_expr.func).endswith("Account") and account_expr.args:
                    recipient_node = account_expr.args[0]
            self.info.transfers.append(
                TransferSite(
                    line=node.lineno,
                    call_name=call_name,
                    recipient=self.resolver.source(recipient_node),
                    amount=self.resolver.source(amount_node),
                    recipient_dependencies=tuple(sorted(self.resolver.dependencies(recipient_node))),
                    amount_dependencies=tuple(sorted(self.resolver.dependencies(amount_node))),
                )
            )
        self.generic_visit(node)


class AstIndex:
    def __init__(self, tree: ast.Module, functions: dict[str, FunctionInfo], contract_classes: dict[str, int]):
        self.tree = tree
        self.functions = functions
        self.contract_classes = contract_classes
        self.analysis_cache: dict[str, object] = {}
        self.analysis_metrics: dict[str, int] = {}

    @classmethod
    def build(cls, source: str) -> "AstIndex":
        tree = ast.parse(source)
        ast_node_count = sum(1 for _ in ast.walk(tree))
        if ast_node_count > MAX_AST_NODES:
            raise AnalysisLimitExceeded("Python AST exceeds the deterministic node budget")
        functions: dict[str, FunctionInfo] = {}
        contract_classes: dict[str, int] = {}
        dependency_budget = _AnalysisBudget(MAX_DEPENDENCY_STEPS, "dependency analysis")

        def collect(body: list[ast.stmt], class_name: str | None = None, parent: str | None = None) -> None:
            for node in body:
                if isinstance(node, ast.ClassDef):
                    if any(dotted_name(base) == "gl.Contract" for base in node.bases):
                        contract_classes[node.name] = node.lineno
                    collect(node.body, node.name, parent)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if parent:
                        qualname = f"{parent}.<locals>.{node.name}"
                    elif class_name:
                        qualname = f"{class_name}.{node.name}"
                    else:
                        qualname = node.name
                    decorators = tuple(dotted_name(item) for item in node.decorator_list)
                    public_kind = None
                    if any(name == "gl.public.write.payable" for name in decorators):
                        public_kind = "payable"
                    elif any(name == "gl.public.write" for name in decorators):
                        public_kind = "write"
                    elif any(name == "gl.public.view" for name in decorators):
                        public_kind = "view"
                    parameters = tuple(
                        arg.arg
                        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                        if arg.arg != "self"
                    )
                    info = FunctionInfo(
                        qualname=qualname,
                        name=node.name,
                        class_name=class_name,
                        parent_qualname=parent,
                        line=node.lineno,
                        decorators=decorators,
                        parameters=parameters,
                        public_kind=public_kind,
                    )
                    scanner = _FunctionScanner(info, node, dependency_budget)
                    for statement in node.body:
                        scanner.visit(statement)
                    info.calls.sort()
                    info.authority_guards.sort()
                    info.transfers.sort()
                    info.consensus_calls.sort()
                    info.nondeterministic_lines.sort()
                    info.web_observation_lines.sort()
                    info.prompt_calls.sort()
                    info.result_guard_parameters.sort()
                    info.bounded_guard_lines.sort()
                    info.url_scheme_guard_lines.sort()
                    info.url_host_guard_lines.sort()
                    info.url_length_guard_lines.sort()
                    info.url_duplicate_guard_lines.sort()
                    info.replay_guard_lines.sort()
                    info.terminal_write_lines.sort()
                    info.state_writes.sort()
                    info.state_write_lines.sort()
                    info.sender_reference_lines.sort()
                    functions[qualname] = info
                    collect(node.body, class_name, qualname)

        collect(tree.body)
        index = cls(tree, functions, contract_classes)
        index.analysis_metrics = {
            "ast_nodes": ast_node_count,
            "dependency_steps": MAX_DEPENDENCY_STEPS - dependency_budget.remaining,
        }
        return index

    @property
    def has_recognizable_contract(self) -> bool:
        return bool(self.contract_classes) and any(
            item.class_name in self.contract_classes and item.public_kind in {"write", "payable"}
            for item in self.functions.values()
        )

    @property
    def public_write_functions(self) -> list[FunctionInfo]:
        return sorted(
            (
                item
                for item in self.functions.values()
                if item.class_name in self.contract_classes and item.public_kind in {"write", "payable"}
            ),
            key=lambda item: item.qualname,
        )

    def resolve_call(self, caller: FunctionInfo, call_name: str) -> str | None:
        if call_name.startswith("self.") and caller.class_name:
            candidate = f"{caller.class_name}.{call_name.split('.', 1)[1]}"
            return candidate if candidate in self.functions else None
        if "." not in call_name:
            nested = f"{caller.qualname}.<locals>.{call_name}"
            if nested in self.functions:
                return nested
            scope = caller.parent_qualname
            while scope:
                candidate = f"{scope}.<locals>.{call_name}"
                if candidate in self.functions:
                    return candidate
                scope = self.functions.get(scope).parent_qualname if scope in self.functions else None
            module_matches = [
                name
                for name, info in self.functions.items()
                if info.class_name is None and info.parent_qualname is None and info.name == call_name
            ]
            if len(module_matches) == 1:
                return module_matches[0]
        return None
