"""Deterministic AST symbol and security-relevant fact index."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Iterable


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
    def __init__(self, parameters: Iterable[str], assignments: dict[str, list[ast.AST]]):
        self.parameters = set(parameters)
        self.assignments = assignments

    def _assignments_before(self, name: str, node: ast.AST) -> list[ast.AST]:
        use_line = getattr(node, "lineno", 0)
        return [value for value in self.assignments.get(name, []) if getattr(value, "lineno", 0) < use_line]

    def dependencies(self, node: ast.AST | None, seen: frozenset[str] = frozenset()) -> set[str]:
        if node is None:
            return set()
        name = dotted_name(node)
        if name == "gl.message.sender_address" or name.startswith("gl.message.sender_address."):
            return {"sender"}
        if name == "gl.message.value" or name.startswith("gl.message.value."):
            return {"message.value"}
        if name == "gl.message_raw" or name.startswith("gl.message_raw"):
            return {"node-time"}
        if name.startswith("self."):
            return {"state"}
        if isinstance(node, ast.Name):
            if node.id in self.parameters:
                return {f"parameter:{node.id}"}
            assignments = self._assignments_before(node.id, node)
            if assignments and node.id not in seen:
                result: set[str] = set()
                for assignment in assignments:
                    result.update(self.dependencies(assignment, seen | {node.id}))
                return result
            return set()
        if isinstance(node, ast.Call) and dotted_name(node.func) == "gl.vm.run_nondet_unsafe":
            return {"consensus-result"}
        if isinstance(node, ast.Call) and dotted_name(node.func).startswith("gl.nondet.web."):
            return {"nondeterministic", "web"}
        if isinstance(node, ast.Call) and dotted_name(node.func).startswith("gl.nondet."):
            return {"model-output", "nondeterministic"}

        result: set[str] = set()
        for child in ast.iter_child_nodes(node):
            result.update(self.dependencies(child, seen))
        return result

    def source(self, node: ast.AST | None, seen: frozenset[str] = frozenset()) -> str:
        if isinstance(node, ast.Name) and node.id not in seen:
            assignments = self._assignments_before(node.id, node)
            if assignments:
                return self.source(assignments[-1], seen | {node.id})
        return rendered(node)


def _contains_blocking(statements: list[ast.stmt]) -> bool:
    return any(isinstance(node, (ast.Raise, ast.Return)) for statement in statements for node in ast.walk(statement))


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
    def __init__(self, info: FunctionInfo, node: ast.FunctionDef | ast.AsyncFunctionDef):
        self.info = info
        self.top_level_statement_ids = {id(statement) for statement in node.body}
        collector = _AssignmentCollector()
        for statement in node.body:
            collector.visit(statement)
        self.resolver = _DependencyResolver(info.parameters, collector.assignments)

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
        expression = rendered(node.test)
        expression_lower = expression.lower()
        dependencies = self.resolver.dependencies(node.test)
        blocking = _contains_blocking(node.body) or _contains_blocking(node.orelse)
        if blocking:
            for call in (item for item in ast.walk(node.test) if isinstance(item, ast.Call)):
                if dotted_name(call.func) != "isinstance" or len(call.args) < 2:
                    continue
                parameter = rendered(call.args[0])
                checked_type = rendered(call.args[1])
                if parameter in self.info.parameters and checked_type in {"gl.vm.Result", "gl.vm.Return"}:
                    self.info.result_guard_parameters.append(parameter)
            if dependencies & {"consensus-result", "model-output"} and isinstance(node.test, (ast.Compare, ast.BoolOp)):
                self.info.bounded_guard_lines.append(node.lineno)
            if "https://" in expression_lower and "startswith" in expression_lower:
                self.info.url_scheme_guard_lines.append(node.lineno)
            if "raw.githubusercontent.com" in expression_lower or "allowed_hosts" in expression_lower:
                self.info.url_host_guard_lines.append(node.lineno)
            if "len(" in expression_lower and any(token in expression_lower for token in ("url", "source")):
                self.info.url_length_guard_lines.append(node.lineno)
            if "set(" in expression_lower and "len(" in expression_lower:
                self.info.url_duplicate_guard_lines.append(node.lineno)
            if "state" in dependencies and any(marker in expression_lower for marker in _TERMINAL_MARKERS):
                self.info.replay_guard_lines.append(node.lineno)
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
    def __init__(self, tree: ast.Module, functions: dict[str, FunctionInfo]):
        self.tree = tree
        self.functions = functions

    @classmethod
    def build(cls, source: str) -> "AstIndex":
        tree = ast.parse(source)
        functions: dict[str, FunctionInfo] = {}

        def collect(body: list[ast.stmt], class_name: str | None = None, parent: str | None = None) -> None:
            for node in body:
                if isinstance(node, ast.ClassDef):
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
                    scanner = _FunctionScanner(info, node)
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
        return cls(tree, functions)

    @property
    def public_write_functions(self) -> list[FunctionInfo]:
        return sorted(
            (item for item in self.functions.values() if item.public_kind in {"write", "payable"}),
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
