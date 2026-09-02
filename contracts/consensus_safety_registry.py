# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""EquivLab consensus-safety registry.

The contract records whether one source-pinned revision meets the named
baseline. MEETS_BASELINE is not formal verification or a security guarantee.
Narrative prose is excluded from the validator equality boundary.
"""

from genlayer import *

import ast
import hashlib
import json
import re
import typing
from urllib.parse import unquote, urlparse


POLICY_VERSION = "gl-consensus-baseline-3"
REPORT_SCHEMA = "equivlab-report-v2"
OBSERVATION_SCHEMA = "equivlab-consensus-observation-v4"
STATUSES = ("MEETS_BASELINE", "WARN", "FAIL", "UNVERIFIABLE")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
RULE_IDS = (
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
RULE_SEVERITY = {
    "AUTH-01": "CRITICAL",
    "BOUND-01": "HIGH",
    "CONS-01": "CRITICAL",
    "EVID-01": "HIGH",
    "PROMPT-01": "HIGH",
    "REPLAY-01": "HIGH",
    "RESULT-01": "HIGH",
    "SRC-01": "CRITICAL",
    "STATE-01": "HIGH",
    "TIME-01": "MEDIUM",
    "URL-01": "MEDIUM",
    "VALUE-01": "CRITICAL",
}
MAX_SOURCE_URL_CHARS = 1000
MAX_SOURCE_BYTES = 100_000
MAX_AST_NODES = 20_000
MAX_DEPENDENCY_STEPS = 100_000
MAX_CALL_GRAPH_STEPS = 20_000
MAX_TRANSFER_PATHS = 4_096
_TERMINAL_MARKERS = ("settled", "withdrawn", "paid", "claimed", "completed", "processed", "finalized")
_PROMPT_MARKERS = ("UNTRUSTED EVIDENCE", "UNTRUSTED_EVIDENCE", "EVIDENCE (DATA ONLY)", "DATA, NOT INSTRUCTIONS")


def _canonical_json(value: typing.Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_source(value: typing.Any) -> str:
    if not isinstance(value, str):
        raise ValueError("source fetch did not return text")
    text = value.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    if not text.endswith("\n"):
        text += "\n"
    if len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("source exceeds policy size bound")
    return text


def _call_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return (prefix + "." + node.attr) if prefix else node.attr
    return ""


def _render(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _is_public_write(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    names = [_call_name(item) for item in node.decorator_list]
    return "gl.public.write" in names or "gl.public.write.payable" in names


def _contract_classes(tree: ast.Module) -> list[ast.ClassDef]:
    return [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and any(_call_name(base) == "gl.Contract" for base in node.bases)
    ]


def _direct_function_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    calls: list[ast.Call] = []

    def walk(item: ast.AST, root: bool = False) -> None:
        if not root and isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return
        if isinstance(item, ast.Call):
            calls.append(item)
        for child in ast.iter_child_nodes(item):
            walk(child)

    walk(node, True)
    return calls


def _method_reaches_consensus(
    name: str,
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> bool:
    reachable = _reachable_method_names(name, methods)
    return bool(reachable) and any(
        _call_name(call.func) == "gl.vm.run_nondet_unsafe"
        for method_name in reachable
        for call in _direct_function_calls(methods[method_name])
    )


def _reachable_method_names(
    root: str,
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[str]:
    output: set[str] = set()
    pending = [root]
    steps = 0
    while pending:
        steps += 1
        if steps > MAX_AST_NODES:
            return []
        current = pending.pop()
        if current in output or current not in methods:
            continue
        output.add(current)
        for call in _direct_function_calls(methods[current]):
            called = _call_name(call.func)
            target = called.split(".", 1)[1] if called.startswith("self.") else called
            if target in methods and target not in output:
                pending.append(target)
    return sorted(output)


def _direct_state_writes(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[int, str, str]]:
    output: list[tuple[int, str, str]] = []

    def walk(item: ast.AST, root: bool = False) -> None:
        if not root and isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return
        if isinstance(item, ast.Assign):
            for target in item.targets:
                target_text = _render(target)
                if target_text.startswith("self."):
                    output.append((item.lineno, target_text, _render(item.value)))
        elif isinstance(item, ast.AnnAssign):
            target_text = _render(item.target)
            if target_text.startswith("self."):
                output.append((item.lineno, target_text, _render(item.value)))
        elif isinstance(item, ast.AugAssign):
            target_text = _render(item.target)
            if target_text.startswith("self."):
                output.append((item.lineno, target_text, _render(item.value)))
        for child in ast.iter_child_nodes(item):
            walk(child)

    walk(node, True)
    return sorted(output)


def _state_order_failures(
    root: str,
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[tuple[int, str, str]]:
    failures: set[tuple[int, str, str]] = set()
    steps = [MAX_AST_NODES]

    def walk(name: str, consensus_seen: bool, seen: frozenset[str]) -> bool:
        steps[0] -= 1
        if steps[0] < 0 or name in seen or name not in methods:
            return consensus_seen
        node = methods[name]
        events: list[tuple[int, int, typing.Any]] = []
        events.extend((line, 0, (target, value)) for line, target, value in _direct_state_writes(node))
        events.extend((call.lineno, 1, call) for call in _direct_function_calls(node))
        for line, kind, event in sorted(events, key=lambda item: (item[0], item[1])):
            if kind == 0:
                if not consensus_seen:
                    failures.add((line, name, event[0]))
                continue
            call = event
            called = _call_name(call.func)
            if called == "gl.vm.run_nondet_unsafe":
                consensus_seen = True
                continue
            target = called.split(".", 1)[1] if called.startswith("self.") else called
            if target in methods:
                consensus_seen = walk(target, consensus_seen, seen | {name})
        return consensus_seen

    if _method_reaches_consensus(root, methods):
        walk(root, False, frozenset())
    return sorted(failures)


def _nested_functions(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        item.name: item
        for item in ast.walk(node)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item is not node
    }


def _calls_matching(node: ast.AST, prefix: str) -> list[ast.Call]:
    return [
        item
        for item in ast.walk(node)
        if isinstance(item, ast.Call) and _call_name(item.func).startswith(prefix)
    ]


def _reaches_call(
    name: str,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    prefix: str,
) -> bool:
    pending = [name]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current in seen or current not in functions:
            continue
        seen.add(current)
        calls = _direct_function_calls(functions[current])
        if any(_call_name(call.func).startswith(prefix) for call in calls):
            return True
        for call in calls:
            called = _call_name(call.func)
            if "." not in called and called in functions and called not in seen:
                pending.append(called)
    return False


def _self_assignments(node: ast.AST) -> list[tuple[int, str, str]]:
    writes: list[tuple[int, str, str]] = []
    for item in ast.walk(node):
        if isinstance(item, ast.Assign):
            for target in item.targets:
                target_text = _render(target)
                if target_text.startswith("self."):
                    writes.append((item.lineno, target_text, _render(item.value)))
        elif isinstance(item, ast.AnnAssign):
            target_text = _render(item.target)
            if target_text.startswith("self."):
                writes.append((item.lineno, target_text, _render(item.value)))
        elif isinstance(item, ast.AugAssign):
            target_text = _render(item.target)
            if target_text.startswith("self."):
                writes.append((item.lineno, target_text, _render(item.value)))
    return sorted(writes)


def _blocking_guard_text(node: ast.FunctionDef | ast.AsyncFunctionDef, before_line: int) -> str:
    pieces: list[str] = []
    for item in ast.walk(node):
        if not isinstance(item, ast.If) or item.lineno >= before_line:
            continue
        blocking = any(isinstance(child, (ast.Raise, ast.Return)) for child in ast.walk(item))
        if blocking:
            pieces.append(_render(item.test))
    return "\n".join(pieces)


def _transfer_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    output: list[ast.Call] = []
    for item in ast.walk(node):
        if not isinstance(item, ast.Call):
            continue
        name = _call_name(item.func)
        if name == "gl.eth_transfer" or name == "emit_transfer" or name.endswith(".emit_transfer"):
            output.append(item)
    return sorted(output, key=lambda item: item.lineno)


def _transfer_fields(call: ast.Call) -> tuple[str, str]:
    recipient = _render(call.args[0]) if call.args else ""
    amount = _render(call.args[1]) if len(call.args) > 1 else ""
    for keyword in call.keywords:
        if keyword.arg in ("to", "recipient", "address"):
            recipient = _render(keyword.value)
        elif keyword.arg in ("value", "amount"):
            amount = _render(keyword.value)
    if (_call_name(call.func) == "emit_transfer" or _call_name(call.func).endswith(".emit_transfer")) and isinstance(call.func, ast.Attribute):
        account = call.func.value
        if isinstance(account, ast.Call) and account.args:
            recipient = _render(account.args[0])
    return recipient, amount


def _transfer_field_nodes(call: ast.Call) -> tuple[ast.AST | None, ast.AST | None]:
    recipient: ast.AST | None = call.args[0] if call.args else None
    amount: ast.AST | None = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg in ("to", "recipient", "address"):
            recipient = keyword.value
        elif keyword.arg in ("value", "amount"):
            amount = keyword.value
    if (
        (_call_name(call.func) == "emit_transfer" or _call_name(call.func).endswith(".emit_transfer"))
        and isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Call)
        and call.func.value.args
    ):
        recipient = call.func.value.args[0]
    return recipient, amount


def _local_aliases(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in node.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    aliases[target.id] = _render(statement.value)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            aliases[statement.target.id] = _render(statement.value)
    return aliases


def _resolve_alias(value: str, aliases: dict[str, str]) -> str:
    seen: set[str] = set()
    current = value
    while current in aliases and current not in seen:
        seen.add(current)
        current = aliases[current]
    return current


def _assignment_nodes(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, list[ast.AST]]:
    assignments: dict[str, list[ast.AST]] = {}

    def collect(item: ast.AST) -> None:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(item.value)
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name) and item.value is not None:
            assignments.setdefault(item.target.id, []).append(item.value)
        for child in ast.iter_child_nodes(item):
            collect(child)

    for statement in node.body:
        collect(statement)
    return assignments


def _dependencies(
    node: ast.AST | None,
    parameters: set[str],
    assignments: dict[str, list[ast.AST]],
    seen: frozenset[str] = frozenset(),
    memo: dict[tuple[int, frozenset[str]], frozenset[str]] | None = None,
    budget: list[int] | None = None,
) -> set[str]:
    if node is None:
        return set()
    if memo is None:
        memo = {}
    if budget is None:
        budget = [MAX_DEPENDENCY_STEPS]
    key = (id(node), seen)
    if key in memo:
        return set(memo[key])
    budget[0] -= 1
    if budget[0] < 0:
        return {"analysis-limit"}
    name = _call_name(node)
    if name == "gl.message.sender_address" or name.startswith("gl.message.sender_address."):
        result = {"sender"}
        memo[key] = frozenset(result)
        return result
    if name == "gl.message.value" or name.startswith("gl.message.value."):
        result = {"message.value"}
        memo[key] = frozenset(result)
        return result
    if name.startswith("self."):
        result = {"state"}
        memo[key] = frozenset(result)
        return result
    if isinstance(node, ast.Name):
        if node.id in parameters:
            result = {"parameter:" + node.id}
            memo[key] = frozenset(result)
            return result
        use_line = getattr(node, "lineno", 0)
        use_column = getattr(node, "col_offset", 0)
        prior = [
            value
            for value in assignments.get(node.id, [])
            if (getattr(value, "lineno", 0), getattr(value, "col_offset", 0)) < (use_line, use_column)
        ]
        if prior and node.id not in seen:
            result: set[str] = set()
            for value in prior:
                result.update(_dependencies(value, parameters, assignments, seen | {node.id}, memo, budget))
            memo[key] = frozenset(result)
            return result
        memo[key] = frozenset()
        return set()
    if isinstance(node, ast.Call) and _call_name(node.func) == "gl.vm.run_nondet_unsafe":
        result = {"consensus-result"}
        memo[key] = frozenset(result)
        return result
    if isinstance(node, ast.Call) and _call_name(node.func).startswith("gl.nondet.web."):
        result = {"nondeterministic", "web"}
        memo[key] = frozenset(result)
        return result
    if isinstance(node, ast.Call) and _call_name(node.func).startswith("gl.nondet."):
        result = {"model-output", "nondeterministic"}
        memo[key] = frozenset(result)
        return result
    result: set[str] = set()
    for child in ast.iter_child_nodes(node):
        result.update(_dependencies(child, parameters, assignments, seen, memo, budget))
    memo[key] = frozenset(result)
    return result


def _unconditionally_blocks(statements: list[ast.stmt]) -> bool:
    if not statements:
        return False
    statement = statements[0]
    if isinstance(statement, (ast.Raise, ast.Return)):
        return True
    return (
        isinstance(statement, ast.If)
        and bool(statement.orelse)
        and _unconditionally_blocks(statement.body)
        and _unconditionally_blocks(statement.orelse)
    )


def _rejects_result(statements: list[ast.stmt]) -> bool:
    if not statements:
        return False
    first = statements[0]
    if isinstance(first, ast.Raise):
        return True
    return isinstance(first, ast.Return) and isinstance(first.value, ast.Constant) and first.value.value is False


def _boolean_entails(node: ast.BoolOp, truth: bool, predicate: typing.Callable[[ast.AST, bool], bool]) -> bool:
    outcomes = [predicate(value, truth) for value in node.values]
    if isinstance(node.op, ast.And):
        return any(outcomes) if truth else all(outcomes)
    return all(outcomes) if truth else any(outcomes)


def _condition_invalid_result(node: ast.AST, truth: bool, parameter: str) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_invalid_result(node.operand, not truth, parameter)
    if isinstance(node, ast.BoolOp):
        return _boolean_entails(node, truth, lambda value, outcome: _condition_invalid_result(value, outcome, parameter))
    if not isinstance(node, ast.Call) or _call_name(node.func) != "isinstance" or len(node.args) < 2:
        return False
    return _render(node.args[0]) == parameter and _render(node.args[1]) == "gl.vm.Return" and not truth


def _result_guard(node: ast.If, parameter: str) -> bool:
    return (_rejects_result(node.body) and _condition_invalid_result(node.test, True, parameter)) or (
        _rejects_result(node.orelse) and _condition_invalid_result(node.test, False, parameter)
    )


def _condition_bounded_rejection(
    node: ast.AST,
    truth: bool,
    parameters: set[str],
    assignments: dict[str, list[ast.AST]],
    memo: dict[tuple[int, frozenset[str]], frozenset[str]],
    budget: list[int],
) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_bounded_rejection(node.operand, not truth, parameters, assignments, memo, budget)
    if isinstance(node, ast.BoolOp):
        return _boolean_entails(
            node,
            truth,
            lambda value, outcome: _condition_bounded_rejection(
                value, outcome, parameters, assignments, memo, budget
            ),
        )
    dependencies = _dependencies(node, parameters, assignments, memo=memo, budget=budget)
    if not isinstance(node, ast.Compare) or not (dependencies & {"consensus-result", "model-output"}):
        return False
    if len(node.ops) != 1:
        return False
    operator = node.ops[0]
    if isinstance(operator, (ast.NotIn, ast.NotEq)):
        return truth
    if isinstance(operator, (ast.In, ast.Eq)):
        return not truth
    return isinstance(operator, (ast.Lt, ast.LtE, ast.Gt, ast.GtE))


def _bounded_guard(
    node: ast.If,
    parameters: set[str],
    assignments: dict[str, list[ast.AST]],
    memo: dict[tuple[int, frozenset[str]], frozenset[str]],
    budget: list[int],
) -> bool:
    return (
        _unconditionally_blocks(node.body)
        and _condition_bounded_rejection(node.test, True, parameters, assignments, memo, budget)
    ) or (
        _unconditionally_blocks(node.orelse)
        and _condition_bounded_rejection(node.test, False, parameters, assignments, memo, budget)
    )


def _condition_terminal_state(
    node: ast.AST,
    truth: bool,
    parameters: set[str],
    assignments: dict[str, list[ast.AST]],
    memo: dict[tuple[int, frozenset[str]], frozenset[str]],
    budget: list[int],
) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_terminal_state(node.operand, not truth, parameters, assignments, memo, budget)
    if isinstance(node, ast.BoolOp):
        return _boolean_entails(
            node,
            truth,
            lambda value, outcome: _condition_terminal_state(
                value, outcome, parameters, assignments, memo, budget
            ),
        )
    expression = _render(node).lower()
    dependencies = _dependencies(node, parameters, assignments, memo=memo, budget=budget)
    if "state" not in dependencies or not any(marker in expression for marker in _TERMINAL_MARKERS):
        return False
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return truth
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        if isinstance(node.ops[0], (ast.Eq, ast.Is, ast.In)):
            return truth
        if isinstance(node.ops[0], (ast.NotEq, ast.IsNot, ast.NotIn)):
            return not truth
    return False


def _replay_guard(
    node: ast.If,
    parameters: set[str],
    assignments: dict[str, list[ast.AST]],
    memo: dict[tuple[int, frozenset[str]], frozenset[str]],
    budget: list[int],
) -> bool:
    return (
        _unconditionally_blocks(node.body)
        and _condition_terminal_state(node.test, True, parameters, assignments, memo, budget)
    ) or (
        _unconditionally_blocks(node.orelse)
        and _condition_terminal_state(node.test, False, parameters, assignments, memo, budget)
    )


def _url_prefix_call(node: ast.AST, subjects: set[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "startswith"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in subjects
        and bool(node.args)
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "https://raw.githubusercontent.com/"
    )


def _len_subject(node: ast.AST, subjects: set[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and _call_name(node.func) == "len"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in subjects
    )


def _len_set_subject(node: ast.AST, subjects: set[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and _call_name(node.func) == "len"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Call)
        and _call_name(node.args[0].func) == "set"
        and len(node.args[0].args) == 1
        and isinstance(node.args[0].args[0], ast.Name)
        and node.args[0].args[0].id in subjects
    )


def _condition_url_invalid(node: ast.AST, truth: bool, kind: str, subjects: set[str]) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _condition_url_invalid(node.operand, not truth, kind, subjects)
    if isinstance(node, ast.BoolOp):
        return _boolean_entails(
            node,
            truth,
            lambda value, outcome: _condition_url_invalid(value, outcome, kind, subjects),
        )
    if kind in ("scheme", "host"):
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


def _url_guard(node: ast.If, kind: str, subjects: set[str]) -> bool:
    return (_unconditionally_blocks(node.body) and _condition_url_invalid(node.test, True, kind, subjects)) or (
        _unconditionally_blocks(node.orelse) and _condition_url_invalid(node.test, False, kind, subjects)
    )


def _authority_condition(
    node: ast.AST,
    truth: bool,
    parameters: set[str],
    assignments: dict[str, list[ast.AST]],
) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _authority_condition(node.operand, not truth, parameters, assignments)
    if isinstance(node, ast.BoolOp):
        if truth and isinstance(node.op, ast.And):
            return any(_authority_condition(value, True, parameters, assignments) for value in node.values)
        if not truth and isinstance(node.op, ast.Or):
            return any(_authority_condition(value, False, parameters, assignments) for value in node.values)
        return False
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return False
    left = _dependencies(node.left, parameters, assignments)
    right = _dependencies(node.comparators[0], parameters, assignments)
    sender_left = left == {"sender"} and right == {"state"}
    sender_right = left == {"state"} and right == {"sender"}
    if not (sender_left or sender_right):
        return False
    operator = node.ops[0]
    if isinstance(operator, ast.Eq):
        return truth
    if isinstance(operator, ast.NotEq):
        return not truth
    if isinstance(operator, ast.In) and sender_left:
        return truth
    if isinstance(operator, ast.NotIn) and sender_left:
        return not truth
    return False


def _has_authority_guard(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    before_line: int,
    parameters: set[str],
) -> bool:
    assignments = _assignment_nodes(node)
    for item in node.body:
        if not isinstance(item, (ast.If, ast.Assert)) or item.lineno >= before_line:
            continue
        message_has_effects = isinstance(item, ast.Assert) and item.msg is not None and any(
            isinstance(child, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr))
            for child in ast.walk(item.msg)
        )
        if (
            isinstance(item, ast.Assert)
            and not message_has_effects
            and _authority_condition(item.test, True, parameters, assignments)
        ):
            return True
        if not isinstance(item, ast.If):
            continue
        if _unconditionally_blocks(item.body) and _authority_condition(item.test, False, parameters, assignments):
            return True
        if _unconditionally_blocks(item.orelse) and _authority_condition(item.test, True, parameters, assignments):
            return True
    return False


def _transfer_paths(
    root: ast.FunctionDef | ast.AsyncFunctionDef,
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> tuple[list[tuple[tuple[str, ...], tuple[int, ...], ast.Call, bool]], bool]:
    paths: list[tuple[tuple[str, ...], tuple[int, ...], ast.Call, bool]] = []
    steps = [0]
    limited = [False]

    def walk(
        current: str,
        functions: tuple[str, ...],
        call_lines: tuple[int, ...],
        guarded_before_entry: bool,
        seen: frozenset[str],
    ) -> None:
        steps[0] += 1
        if steps[0] > MAX_CALL_GRAPH_STEPS or len(paths) > MAX_TRANSFER_PATHS:
            limited[0] = True
            return
        if current in seen or current not in methods:
            return
        function = methods[current]
        parameters = {arg.arg for arg in function.args.args if arg.arg != "self"}
        next_seen = seen | {current}
        for transfer in _transfer_calls(function):
            guarded = guarded_before_entry or _has_authority_guard(function, transfer.lineno, parameters)
            paths.append((functions, call_lines, transfer, guarded))
            if len(paths) > MAX_TRANSFER_PATHS:
                limited[0] = True
                return
        for call in _direct_function_calls(function):
            called = _call_name(call.func)
            target = called.split(".", 1)[1] if called.startswith("self.") else called
            if target not in methods or target in next_seen:
                continue
            guarded_at_call = guarded_before_entry or _has_authority_guard(function, call.lineno, parameters)
            walk(
                target,
                functions + (target,),
                call_lines + (call.lineno,),
                guarded_at_call,
                next_seen,
            )
            if limited[0]:
                return

    walk(root.name, (root.name,), (), False, frozenset())
    paths.sort(key=lambda item: (item[2].lineno, item[0], item[1]))
    return paths, limited[0]


def _path_has_ordered_replay_fact(
    functions: tuple[str, ...],
    call_lines: tuple[int, ...],
    transfer_line: int,
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    fact: str,
) -> tuple[bool, bool]:
    for offset, name in enumerate(functions):
        function = methods[name]
        cutoff = transfer_line if offset == len(functions) - 1 else call_lines[offset]
        if fact == "write":
            if any(
                line < cutoff and any(marker in target.lower() for marker in _TERMINAL_MARKERS)
                for line, target, _value in _direct_state_writes(function)
            ):
                return True, False
            continue
        parameters = {arg.arg for arg in function.args.args if arg.arg != "self"}
        assignments = _assignment_nodes(function)
        memo: dict[tuple[int, frozenset[str]], frozenset[str]] = {}
        budget = [MAX_DEPENDENCY_STEPS]
        for item in function.body:
            if not isinstance(item, ast.If) or item.lineno >= cutoff:
                continue
            if _replay_guard(item, parameters, assignments, memo, budget):
                return True, False
            if budget[0] < 0:
                return False, True
    return False, False


def _deterministic_findings(source: str, source_url: str) -> tuple[list[str], list[str]]:
    tree = ast.parse(source)
    if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
        return [], list(RULE_IDS)
    failed: set[str] = set()
    unverifiable: set[str] = set()
    try:
        _validate_source_url(source_url)
    except ValueError:
        failed.add("SRC-01")

    contracts = _contract_classes(tree)
    public_scopes: list[
        tuple[
            ast.FunctionDef | ast.AsyncFunctionDef,
            dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
            list[str],
        ]
    ] = []
    has_consensus_path = False
    for contract in contracts:
        methods = {
            item.name: item
            for item in contract.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        writes = [item for item in methods.values() if _is_public_write(item)]
        for root in writes:
            reachable = _reachable_method_names(root.name, methods)
            if not reachable:
                return [], list(RULE_IDS)
            public_scopes.append((root, methods, reachable))
            if _method_reaches_consensus(root.name, methods):
                has_consensus_path = True

    if not contracts or not public_scopes:
        return [], sorted(rule for rule in RULE_IDS if rule != "SRC-01")
    if not has_consensus_path:
        unverifiable.add("CONS-01")
    for root, methods, reachable in public_scopes:
        root_parameters = [arg.arg for arg in root.args.args if arg.arg != "self"]
        root_parameter_set = set(root_parameters)
        root_aliases = _local_aliases(root)
        for _line, _method, _target in _state_order_failures(root.name, methods):
            failed.add("STATE-01")

        has_web = any(_calls_matching(methods[name], "gl.nondet.web.") for name in reachable)
        url_parameters = {name for name in root_parameters if "url" in name.lower() or "source" in name.lower()}
        if has_web and url_parameters:
            guards = [item for item in root.body if isinstance(item, ast.If)]
            for kind in ("scheme", "host", "length"):
                if not any(_url_guard(item, kind, url_parameters) for item in guards):
                    failed.add("URL-01")
            if any(name.lower().endswith("s") for name in url_parameters) and not any(
                _url_guard(item, "duplicate", url_parameters) for item in guards
            ):
                failed.add("URL-01")

        for method_name in reachable:
            function = methods[method_name]
            parameters = [arg.arg for arg in function.args.args if arg.arg != "self"]
            parameter_set = set(parameters)
            assignments = _assignment_nodes(function)
            dependency_memo: dict[tuple[int, frozenset[str]], frozenset[str]] = {}
            dependency_budget = [MAX_DEPENDENCY_STEPS]
            nested = _nested_functions(function)
            consensus_calls = [
                item
                for item in _direct_function_calls(function)
                if _call_name(item.func) == "gl.vm.run_nondet_unsafe"
            ]

            for consensus in consensus_calls:
                leader_name = _render(consensus.args[0]) if len(consensus.args) > 0 else ""
                validator_name = _render(consensus.args[1]) if len(consensus.args) > 1 else ""
                validator = nested.get(validator_name)
                if validator is None or not _reaches_call(validator_name, nested, "gl.nondet."):
                    failed.add("CONS-01")
                validator_parameter = ""
                if validator is not None:
                    validator_parameters = [arg.arg for arg in validator.args.args if arg.arg != "self"]
                    validator_parameter = validator_parameters[0] if validator_parameters else ""
                if not validator_parameter or not any(
                    isinstance(item, ast.If) and _result_guard(item, validator_parameter)
                    for item in (validator.body if validator is not None else [])
                ):
                    failed.add("RESULT-01")
                if _reaches_call(leader_name, nested, "gl.nondet.web.") and not _reaches_call(
                    validator_name, nested, "gl.nondet.web."
                ):
                    failed.add("EVID-01")
                for callback_name in (leader_name, validator_name):
                    if callback_name in nested and _self_assignments(nested[callback_name]):
                        failed.add("STATE-01")

            web_calls = _calls_matching(function, "gl.nondet.web.")
            function_text = _render(function)
            for prompt_call in _calls_matching(function, "gl.nondet.exec_prompt"):
                enclosing_text = function_text.upper()
                if (web_calls or parameter_set) and not any(marker in enclosing_text for marker in _PROMPT_MARKERS):
                    prompt_arg = _render(prompt_call.args[0]) if prompt_call.args else ""
                    if not any(marker in prompt_arg.upper() for marker in _PROMPT_MARKERS):
                        failed.add("PROMPT-01")

            bounded_lines = [
                item.lineno
                for item in function.body
                if isinstance(item, ast.If)
                and _bounded_guard(item, parameter_set, assignments, dependency_memo, dependency_budget)
            ]
            for statement in function.body:
                value: ast.AST | None = None
                targets: list[ast.AST] = []
                if isinstance(statement, ast.Assign):
                    value = statement.value
                    targets = list(statement.targets)
                elif isinstance(statement, ast.AnnAssign):
                    value = statement.value
                    targets = [statement.target]
                elif isinstance(statement, ast.AugAssign):
                    value = statement.value
                    targets = [statement.target]
                if value is None or not any(_render(target).startswith("self.") for target in targets):
                    continue
                dependencies = _dependencies(
                    value,
                    parameter_set,
                    assignments,
                    memo=dependency_memo,
                    budget=dependency_budget,
                )
                if "analysis-limit" in dependencies:
                    return [], list(RULE_IDS)
                if dependencies & {"consensus-result", "model-output"} and not any(
                    line < statement.lineno for line in bounded_lines
                ):
                    failed.add("BOUND-01")

            for line, target, value in _direct_state_writes(function):
                target_lower = target.lower()
                if any(marker in target_lower for marker in ("time", "timestamp", "created_at", "updated_at")):
                    if any(re.search(r"\b" + re.escape(parameter) + r"\b", value) for parameter in parameters):
                        failed.add("TIME-01")

        transfer_paths, transfer_limited = _transfer_paths(root, methods)
        if transfer_limited:
            unverifiable.update(("AUTH-01", "REPLAY-01", "VALUE-01"))
            continue
        for functions, call_lines, transfer, has_authority in transfer_paths:
            function = methods[functions[-1]]
            parameters = {arg.arg for arg in function.args.args if arg.arg != "self"}
            assignments = _assignment_nodes(function)
            dependency_memo: dict[tuple[int, frozenset[str]], frozenset[str]] = {}
            dependency_budget = [MAX_DEPENDENCY_STEPS]
            recipient_node, amount_node = _transfer_field_nodes(transfer)
            recipient_dependencies = _dependencies(
                recipient_node,
                parameters,
                assignments,
                memo=dependency_memo,
                budget=dependency_budget,
            )
            amount_dependencies = _dependencies(
                amount_node,
                parameters,
                assignments,
                memo=dependency_memo,
                budget=dependency_budget,
            )
            if "analysis-limit" in recipient_dependencies | amount_dependencies:
                unverifiable.update(("AUTH-01", "VALUE-01"))
                continue
            if not has_authority:
                failed.add("AUTH-01")
            if amount_node is None or "message.value" in amount_dependencies or any(
                dependency.startswith("parameter:") for dependency in amount_dependencies
            ):
                failed.add("VALUE-01")
            if amount_dependencies & {"nondeterministic", "consensus-result", "model-output"}:
                failed.add("VALUE-01")
            caller_recipient = bool(recipient_dependencies & {"sender", "message.value"}) or any(
                dependency.startswith("parameter:") for dependency in recipient_dependencies
            )
            if caller_recipient and not has_authority:
                failed.add("VALUE-01")
            if recipient_dependencies & {"nondeterministic", "consensus-result", "model-output"}:
                failed.add("VALUE-01")

            _recipient, amount = _transfer_fields(transfer)
            amount = _resolve_alias(amount, _local_aliases(function))
            if "balance" not in amount.lower():
                has_guard, guard_limited = _path_has_ordered_replay_fact(
                    functions,
                    call_lines,
                    transfer.lineno,
                    methods,
                    "guard",
                )
                has_effect, effect_limited = _path_has_ordered_replay_fact(
                    functions,
                    call_lines,
                    transfer.lineno,
                    methods,
                    "write",
                )
                if guard_limited or effect_limited:
                    unverifiable.add("REPLAY-01")
                elif not has_guard or not has_effect:
                    failed.add("REPLAY-01")

    return sorted(failed), sorted(unverifiable)


def _severity(failed: list[str], warnings: list[str]) -> str:
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    rules = failed + warnings
    if not rules:
        return "LOW"
    return max((RULE_SEVERITY[rule] for rule in rules), key=lambda item: order[item])


def _build_observation(
    source_url: str,
    source_hash: str,
    status: str,
    failed: list[str],
    warnings: list[str],
    unverifiable: list[str],
) -> dict[str, typing.Any]:
    failed = sorted(failed)
    warnings = sorted(warnings)
    unverifiable = sorted(unverifiable)
    severity = _severity(failed, warnings + unverifiable)
    findings = [
        {
            "evidence": [],
            "rule": rule,
            "severity": RULE_SEVERITY[rule],
            "status": status_name,
            "summary": "The on-chain deterministic core emitted " + status_name + " for " + rule + ".",
        }
        for status_name, rules in (("FAIL", failed), ("WARN", warnings), ("UNVERIFIABLE", unverifiable))
        for rule in rules
    ]
    findings.sort(key=lambda item: item["rule"])
    report = {
        "failed_rules": failed,
        "findings": findings,
        "implemented_rules": sorted(RULE_IDS),
        "policy": POLICY_VERSION,
        "schema": REPORT_SCHEMA,
        "scope": "Twelve deterministic baseline rules; not formal verification or a security guarantee.",
        "severity": severity,
        "source": {"canonical_sha256": source_hash, "mode": "retrieved", "url": source_url},
        "status": status,
        "unverifiable_rules": unverifiable,
        "warning_rules": warnings,
    }
    report["report_sha256"] = _sha256_text(_canonical_json(report))
    return {
        "failed_rules": failed,
        "observation_schema": OBSERVATION_SCHEMA,
        "policy": POLICY_VERSION,
        "report": report,
        "severity": severity,
        "source_hash": source_hash,
        "status": status,
        "unverifiable_rules": unverifiable,
        "warning_rules": warnings,
    }


def _unverifiable(source_url: str, source_hash: str, rules: list[str]) -> dict[str, typing.Any]:
    return _build_observation(source_url, source_hash, "UNVERIFIABLE", [], [], rules)


def _audit_source(source_url: str, submitted_hash: str) -> dict[str, typing.Any]:
    try:
        response = gl.nondet.web.get(source_url)
        fetched = response.body.decode("utf-8")
        source = _canonical_source(fetched)
    except Exception:
        return _unverifiable(source_url, submitted_hash, list(RULE_IDS))

    actual_hash = _sha256_text(source)
    if actual_hash != submitted_hash:
        return _unverifiable(source_url, submitted_hash, list(RULE_IDS))
    try:
        ast.parse(source)
        deterministic_failed, deterministic_unverifiable = _deterministic_findings(source, source_url)
    except Exception:
        return _unverifiable(source_url, submitted_hash, [rule for rule in RULE_IDS if rule != "SRC-01"])

    if deterministic_failed:
        return _build_observation(source_url, submitted_hash, "FAIL", deterministic_failed, [], deterministic_unverifiable)
    if deterministic_unverifiable:
        return _unverifiable(source_url, submitted_hash, deterministic_unverifiable)
    return _build_observation(source_url, submitted_hash, "MEETS_BASELINE", [], [], [])


def _valid_sorted_rule_list(value: typing.Any) -> bool:
    return (
        isinstance(value, list)
        and value == sorted(value)
        and len(value) == len(set(value))
        and all(isinstance(item, str) and item in RULE_IDS for item in value)
    )


def _validate_observation(value: typing.Any, source_hash: str, source_url: str) -> bool:
    if not isinstance(value, dict):
        return False
    required = {
        "failed_rules",
        "observation_schema",
        "policy",
        "report",
        "severity",
        "source_hash",
        "status",
        "unverifiable_rules",
        "warning_rules",
    }
    if set(value.keys()) != required:
        return False
    if value["observation_schema"] != OBSERVATION_SCHEMA or value["policy"] != POLICY_VERSION:
        return False
    if value["source_hash"] != source_hash or value["status"] not in STATUSES or value["severity"] not in SEVERITIES:
        return False
    if not all(_valid_sorted_rule_list(value[key]) for key in ("failed_rules", "warning_rules", "unverifiable_rules")):
        return False
    if set(value["failed_rules"]) & set(value["warning_rules"]):
        return False
    expected_status = "MEETS_BASELINE"
    if value["failed_rules"]:
        expected_status = "FAIL"
    elif value["unverifiable_rules"]:
        expected_status = "UNVERIFIABLE"
    elif value["warning_rules"]:
        expected_status = "WARN"
    if value["status"] != expected_status:
        return False
    if value["severity"] != _severity(value["failed_rules"], value["warning_rules"] + value["unverifiable_rules"]):
        return False
    report = value["report"]
    if not isinstance(report, dict) or not isinstance(report.get("report_sha256"), str):
        return False
    expected_report_keys = {
        "failed_rules",
        "findings",
        "implemented_rules",
        "policy",
        "report_sha256",
        "schema",
        "scope",
        "severity",
        "source",
        "status",
        "unverifiable_rules",
        "warning_rules",
    }
    if set(report.keys()) != expected_report_keys or report["implemented_rules"] != sorted(RULE_IDS):
        return False
    expected_finding_status = {
        **{rule: "FAIL" for rule in value["failed_rules"]},
        **{rule: "WARN" for rule in value["warning_rules"]},
        **{rule: "UNVERIFIABLE" for rule in value["unverifiable_rules"]},
    }
    findings = report["findings"]
    if not isinstance(findings, list) or [item.get("rule") for item in findings if isinstance(item, dict)] != sorted(
        expected_finding_status
    ):
        return False
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding.keys()) != {"evidence", "rule", "severity", "status", "summary"}
            or finding["status"] != expected_finding_status.get(finding["rule"])
            or finding["severity"] != RULE_SEVERITY.get(finding["rule"])
            or not isinstance(finding["summary"], str)
            or finding["evidence"] != []
        ):
            return False
    unsigned = dict(report)
    claimed_hash = unsigned.pop("report_sha256")
    if _sha256_text(_canonical_json(unsigned)) != claimed_hash:
        return False
    for key in ("policy", "status", "severity", "failed_rules", "warning_rules", "unverifiable_rules"):
        if report.get(key) != value[key]:
            return False
    if report.get("schema") != REPORT_SCHEMA:
        return False
    source = report.get("source")
    if (
        not isinstance(source, dict)
        or source.get("canonical_sha256") != source_hash
        or source.get("mode") != "retrieved"
        or source.get("url") != source_url
    ):
        return False
    return True


def _decision_signature(value: dict[str, typing.Any]) -> tuple[typing.Any, ...]:
    return (
        value["observation_schema"],
        value["policy"],
        value["source_hash"],
        value["status"],
        value["severity"],
        tuple(value["failed_rules"]),
        tuple(value["warning_rules"]),
        tuple(value["unverifiable_rules"]),
    )


def _validate_source_url(source_url: str) -> str:
    clean_url = source_url.strip()
    if source_url != clean_url or len(clean_url) == 0 or len(clean_url) > MAX_SOURCE_URL_CHARS:
        raise ValueError("source URL is empty, padded, or too long")
    if any(ord(character) < 32 for character in source_url):
        raise ValueError("source URL contains control characters")
    parsed = urlparse(clean_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("source URL contains an invalid port") from exc
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").lower() != "raw.githubusercontent.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        raise ValueError(
            "source URL must use the approved raw GitHub HTTPS host without credentials, ports, query, or fragment"
        )
    if "%" in parsed.path or "//" in parsed.path or parsed.path.endswith("/"):
        raise ValueError("source URL path must use an unencoded canonical file path")
    encoded_parts = [part for part in parsed.path.split("/") if part]
    decoded_parts = [unquote(part) for part in encoded_parts]
    if (
        len(decoded_parts) < 4
        or re.fullmatch(r"[0-9a-f]{40}", decoded_parts[2]) is None
        or any(part in (".", "..") or "/" in part or "\\" in part or "\x00" in part for part in decoded_parts)
    ):
        raise ValueError("source URL must contain an organization, repository, full commit SHA, and file path")
    return clean_url


def _source_key(source_url: str, source_hash: str, policy_version: str) -> str:
    return _sha256_text(_canonical_json([source_url, source_hash, policy_version]))


class ConsensusSafetyRegistry(gl.Contract):
    audits: DynArray[str]
    reports: DynArray[str]
    latest_by_source_identity_policy: TreeMap[str, u64]
    superseded_by: TreeMap[u64, u64]
    challenges: DynArray[str]
    challenge_ids_by_audit: TreeMap[str, u64]
    challenge_count_by_audit: TreeMap[u64, u64]
    next_audit_id: u64
    next_challenge_id: u64

    def __init__(self):
        self.next_audit_id = u64(0)
        self.next_challenge_id = u64(0)

    @gl.public.write
    def request_audit(self, source_url: str, source_hash: str, policy_version: str) -> u64:
        return self._request_audit(source_url, source_hash, policy_version, None)

    @gl.public.write
    def request_superseding_audit(
        self,
        source_url: str,
        source_hash: str,
        policy_version: str,
        supersedes_id: u64,
    ) -> u64:
        return self._request_audit(source_url, source_hash, policy_version, int(supersedes_id))

    def _request_audit(
        self,
        source_url: str,
        source_hash: str,
        policy_version: str,
        superseded: int | None,
    ) -> u64:
        clean_url = _validate_source_url(source_url)
        clean_hash = source_hash.lower().removeprefix("sha256:")
        if re.fullmatch(r"[0-9a-f]{64}", clean_hash) is None:
            raise ValueError("source_hash must be a canonical SHA-256")
        if policy_version != POLICY_VERSION:
            raise ValueError("unsupported policy version")

        count = int(self.next_audit_id)
        if superseded is not None and (superseded < 0 or superseded >= count):
            raise ValueError("superseded audit does not exist")
        key = _source_key(clean_url, clean_hash, policy_version)
        if key in self.latest_by_source_identity_policy:
            raise ValueError("duplicate source identity and policy audit")
        if superseded is not None and u64(superseded) in self.superseded_by:
            raise ValueError("audit has already been superseded")
        if superseded is not None:
            old = json.loads(self.audits[superseded])
            if old["requester"] != str(gl.message.sender_address):
                raise ValueError("only the original requester may supersede an audit")
            if old["policy"] != policy_version:
                raise ValueError("superseding audit must use the same policy")
            if old["source_url"] == clean_url and old["source_hash"] == clean_hash:
                raise ValueError("superseding audit must use a distinct source identity")

        def independently_audit() -> dict[str, typing.Any]:
            return _audit_source(clean_url, clean_hash)

        def validate_audit(leader_result: gl.vm.Result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            leader_payload = leader_result.calldata
            if not _validate_observation(leader_payload, clean_hash, clean_url):
                return False
            validator_payload = independently_audit()
            if not _validate_observation(validator_payload, clean_hash, clean_url):
                return False
            return _decision_signature(leader_payload) == _decision_signature(validator_payload)

        result = gl.vm.run_nondet_unsafe(independently_audit, validate_audit)
        if not _validate_observation(result, clean_hash, clean_url):
            raise ValueError("consensus returned an invalid EquivLab observation")

        audit_id = self.next_audit_id
        audit = {
            "challenged": False,
            "challenge_count": 0,
            "created_at": gl.message_raw["datetime"],
            "id": str(audit_id),
            "policy": policy_version,
            "requester": str(gl.message.sender_address),
            "source_hash": clean_hash,
            "source_url": clean_url,
            "status": result["status"],
            "superseded_by": None,
            "supersedes_id": str(superseded) if superseded is not None else None,
        }
        self.audits.append(_canonical_json(audit))
        self.reports.append(_canonical_json(result["report"]))
        self.latest_by_source_identity_policy[key] = audit_id
        if superseded is not None:
            old = json.loads(self.audits[superseded])
            old["superseded_by"] = str(audit_id)
            self.audits[superseded] = _canonical_json(old)
            self.superseded_by[u64(superseded)] = audit_id
        self.next_audit_id = u64(count + 1)
        return audit_id

    @gl.public.view
    def get_audit(self, audit_id: u64) -> str:
        index = int(audit_id)
        if index < 0 or index >= int(self.next_audit_id):
            raise ValueError("audit does not exist")
        return self.audits[index]

    @gl.public.view
    def get_report(self, audit_id: u64) -> str:
        index = int(audit_id)
        if index < 0 or index >= int(self.next_audit_id):
            raise ValueError("audit does not exist")
        return self.reports[index]

    @gl.public.view
    def get_latest(self, source_url: str, source_hash: str, policy_version: str) -> str:
        clean_url = _validate_source_url(source_url)
        clean_hash = source_hash.lower().removeprefix("sha256:")
        if re.fullmatch(r"[0-9a-f]{64}", clean_hash) is None or policy_version != POLICY_VERSION:
            return ""
        key = _source_key(clean_url, clean_hash, policy_version)
        if key not in self.latest_by_source_identity_policy:
            return ""
        return str(self.latest_by_source_identity_policy[key])

    @gl.public.write
    def challenge(self, audit_id: u64, reason_hash: str) -> str:
        index = int(audit_id)
        clean_reason = reason_hash.lower().removeprefix("sha256:")
        if index < 0 or index >= int(self.next_audit_id):
            raise ValueError("audit does not exist")
        if re.fullmatch(r"[0-9a-f]{64}", clean_reason) is None:
            raise ValueError("reason_hash must be a canonical SHA-256")
        audit = json.loads(self.audits[index])
        challenge_id = self.next_challenge_id
        challenge_index = int(audit["challenge_count"])
        challenge_record = {
            "audit_id": str(audit_id),
            "challenged_at": gl.message_raw["datetime"],
            "challenger": str(gl.message.sender_address),
            "id": str(challenge_id),
            "reason_hash": clean_reason,
        }
        self.challenges.append(_canonical_json(challenge_record))
        self.challenge_ids_by_audit[str(audit_id) + ":" + str(challenge_index)] = challenge_id
        self.challenge_count_by_audit[u64(index)] = u64(challenge_index + 1)
        audit["challenged"] = True
        audit["challenge_count"] = challenge_index + 1
        self.audits[index] = _canonical_json(audit)
        self.next_challenge_id = u64(int(challenge_id) + 1)
        return str(challenge_id)

    @gl.public.view
    def get_challenge(self, challenge_id: u64) -> str:
        index = int(challenge_id)
        if index < 0 or index >= int(self.next_challenge_id):
            raise ValueError("challenge does not exist")
        return self.challenges[index]

    @gl.public.view
    def get_challenge_count(self, audit_id: u64) -> u64:
        index = int(audit_id)
        if index < 0 or index >= int(self.next_audit_id):
            raise ValueError("audit does not exist")
        if u64(index) not in self.challenge_count_by_audit:
            return u64(0)
        return self.challenge_count_by_audit[u64(index)]

    @gl.public.view
    def get_audit_challenge(self, audit_id: u64, challenge_index: u64) -> str:
        audit = int(audit_id)
        item = int(challenge_index)
        count = int(self.get_challenge_count(audit_id))
        if item < 0 or item >= count:
            raise ValueError("audit challenge does not exist")
        challenge_id = self.challenge_ids_by_audit[str(audit) + ":" + str(item)]
        return self.get_challenge(challenge_id)

    @gl.public.view
    def count(self) -> u64:
        return self.next_audit_id
