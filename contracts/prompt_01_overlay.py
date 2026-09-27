# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Consensus-backed PROMPT-01 correction for the deployed baseline-3 registry.

The original registry remains immutable. This contract reads a specific audit,
rechecks the same pinned source through GenLayer consensus, and stores a
source-matched composite report. It changes only PROMPT-01.
"""

from genlayer import Address, TreeMap, gl, u64

import ast
import hashlib
import json


POLICY = "gl-consensus-baseline-3"
RULES = (
    "AUTH-01", "BOUND-01", "CONS-01", "EVID-01", "PROMPT-01", "REPLAY-01",
    "RESULT-01", "SRC-01", "STATE-01", "TIME-01", "URL-01", "VALUE-01",
)
SEVERITY = {
    "AUTH-01": "CRITICAL", "BOUND-01": "HIGH", "CONS-01": "CRITICAL",
    "EVID-01": "HIGH", "PROMPT-01": "HIGH", "REPLAY-01": "HIGH",
    "RESULT-01": "HIGH", "SRC-01": "CRITICAL", "STATE-01": "HIGH",
    "TIME-01": "MEDIUM", "URL-01": "MEDIUM", "VALUE-01": "CRITICAL",
}
MARKERS = ("UNTRUSTED EVIDENCE", "UNTRUSTED_EVIDENCE", "EVIDENCE (DATA ONLY)", "DATA, NOT INSTRUCTIONS")


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return (prefix + "." + node.attr) if prefix else node.attr
    return ""


def _direct_calls(node: ast.AST) -> list[ast.Call]:
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


def _reachable(root: str, methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]) -> set[str]:
    pending = [root]
    seen: set[str] = set()
    while pending:
        if len(seen) > 20_000:
            raise ValueError("call graph limit")
        name = pending.pop()
        if name in seen or name not in methods:
            continue
        seen.add(name)
        for call in _direct_calls(methods[name]):
            target = _name(call.func)
            if target.startswith("self."):
                target = target[5:]
            if target in methods:
                pending.append(target)
    return seen


def _static_text(node: ast.AST, scope: ast.AST, helpers: dict[str, ast.AST], depth: int = 0) -> str:
    if depth > 8:
        return ""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else ""
    if isinstance(node, ast.Name):
        assignments = [
            item.value for item in ast.walk(scope)
            if isinstance(item, (ast.Assign, ast.AnnAssign))
            and getattr(item, "lineno", 0) < getattr(node, "lineno", 0)
            and (
                isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name) and item.target.id == node.id
                or isinstance(item, ast.Assign) and any(isinstance(target, ast.Name) and target.id == node.id for target in item.targets)
            )
        ]
        return _static_text(assignments[-1], scope, helpers, depth + 1) if assignments else ""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        helper = helpers.get(node.func.id)
        if isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef)) and len(helper.body) == 1 and isinstance(helper.body[0], ast.Return):
            return _static_text(helper.body[0].value, helper, helpers, depth + 1)
    if isinstance(node, ast.JoinedStr):
        return " ".join(_static_text(item.value if isinstance(item, ast.FormattedValue) else item, scope, helpers, depth + 1) for item in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _static_text(node.left, scope, helpers, depth + 1) + " " + _static_text(node.right, scope, helpers, depth + 1)
    return ""


def _prompt_status(source: str) -> str:
    tree = ast.parse(source)
    if sum(1 for _ in ast.walk(tree)) > 20_000:
        return "UNVERIFIABLE"
    helpers = {item.name: item for item in tree.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
    found_contract = False
    found_consensus = False
    failed = False
    unknown = False
    for contract in tree.body:
        if not isinstance(contract, ast.ClassDef) or not any(_name(base) == "gl.Contract" for base in contract.bases):
            continue
        found_contract = True
        methods = {item.name: item for item in contract.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for root in methods.values():
            if not any(_name(decorator) in ("gl.public.write", "gl.public.write.payable") for decorator in root.decorator_list):
                continue
            reachable = _reachable(root.name, methods)
            for method_name in reachable:
                method = methods[method_name]
                if any(_name(call.func) == "gl.vm.run_nondet_unsafe" for call in _direct_calls(method)):
                    found_consensus = True
                scopes = [method] + [item for item in ast.walk(method) if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item is not method]
                has_web = any(_name(call.func).startswith("gl.nondet.web.") for call in ast.walk(method) if isinstance(call, ast.Call))
                has_parameters = any(arg.arg != "self" for arg in method.args.args)
                for scope in scopes:
                    for call in _direct_calls(scope):
                        if _name(call.func) != "gl.nondet.exec_prompt":
                            continue
                        expression = call.args[0] if call.args else ast.Constant(value="")
                        if isinstance(expression, ast.Constant):
                            continue
                        text = _static_text(expression, scope, helpers).upper()
                        framed = any(marker in text for marker in MARKERS) or (
                            "UNTRUSTED" in text and "AS DATA" in text and "IGNORE ANY INSTRUCTIONS" in text
                        )
                        if not framed:
                            if has_web or has_parameters:
                                failed = True
                            else:
                                unknown = True
    if not found_contract or not found_consensus:
        return "UNVERIFIABLE"
    if failed:
        return "FAIL"
    return "UNVERIFIABLE" if unknown else "MEETS_BASELINE"


def _source_result(url: str, expected_hash: str) -> str:
    try:
        source = gl.nondet.web.get(url).body.decode("utf-8")
        source = source.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
        if not source.endswith("\n"):
            source += "\n"
        if len(source.encode("utf-8")) > 100_000 or _hash(source) != expected_hash:
            return "UNVERIFIABLE"
        return _prompt_status(source)
    except Exception:
        return "UNVERIFIABLE"


def _checked_base(audit: dict, report: dict) -> None:
    if audit.get("policy") != POLICY or report.get("policy") != POLICY:
        raise ValueError("base policy mismatch")
    if report.get("schema") != "equivlab-report-v2" or report.get("implemented_rules") != list(RULES):
        raise ValueError("base report schema mismatch")
    source = report.get("source")
    if not isinstance(source, dict) or source.get("mode") != "retrieved":
        raise ValueError("base source missing")
    if source.get("url") != audit.get("source_url") or source.get("canonical_sha256") != audit.get("source_hash"):
        raise ValueError("base source identity mismatch")
    if report.get("status") != audit.get("status"):
        raise ValueError("base audit status mismatch")
    unsigned = dict(report)
    digest = unsigned.pop("report_sha256", None)
    if not isinstance(digest, str) or _hash(_json(unsigned)) != digest:
        raise ValueError("base report hash mismatch")
    for key in ("failed_rules", "warning_rules", "unverifiable_rules"):
        values = report.get(key)
        if not isinstance(values, list) or values != sorted(set(values)) or any(rule not in RULES for rule in values):
            raise ValueError("base rule list invalid")


def _composite(report: dict, outcome: str) -> dict:
    result = dict(report)
    groups = {
        "failed_rules": set(report["failed_rules"]) - {"PROMPT-01"},
        "warning_rules": set(report["warning_rules"]) - {"PROMPT-01"},
        "unverifiable_rules": set(report["unverifiable_rules"]) - {"PROMPT-01"},
    }
    if outcome == "FAIL":
        groups["failed_rules"].add("PROMPT-01")
    elif outcome == "UNVERIFIABLE":
        groups["unverifiable_rules"].add("PROMPT-01")
    for key, values in groups.items():
        result[key] = sorted(values)
    result["status"] = (
        "FAIL" if groups["failed_rules"] else
        "UNVERIFIABLE" if groups["unverifiable_rules"] else
        "WARN" if groups["warning_rules"] else "MEETS_BASELINE"
    )
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    affected = set().union(*groups.values())
    result["severity"] = max((SEVERITY[rule] for rule in affected), key=lambda value: rank[value], default="LOW")
    findings = [item for item in report["findings"] if item.get("rule") != "PROMPT-01"]
    if outcome != "MEETS_BASELINE":
        findings.append({
            "evidence": [], "rule": "PROMPT-01", "severity": "HIGH", "status": outcome,
            "summary": "The consensus-backed PROMPT-01 correction returned " + outcome + ".",
        })
    result["findings"] = sorted(findings, key=lambda item: item["rule"])
    result["scope"] = "Baseline-3 registry decision with consensus-backed PROMPT-01 correction; not formal verification."
    result.pop("report_sha256", None)
    result["report_sha256"] = _hash(_json(result))
    return result


class Prompt01Overlay(gl.Contract):
    base_registry: str
    patches: TreeMap[u64, str]
    reports: TreeMap[u64, str]

    def __init__(self, registry_address: Address):
        registry_address = str(registry_address)
        if len(registry_address) != 42 or not registry_address.startswith("0x") or any(character not in "0123456789abcdefABCDEF" for character in registry_address[2:]):
            raise ValueError("registry address must be a 20-byte hex address")
        self.base_registry = registry_address

    @gl.public.write
    def reconcile(self, audit_id: u64) -> str:
        if audit_id in self.patches:
            raise ValueError("audit already reconciled")
        base = gl.get_contract_at(Address(self.base_registry))
        audit = json.loads(base.view().get_audit(audit_id))
        report = json.loads(base.view().get_report(audit_id))
        if not isinstance(audit, dict) or not isinstance(report, dict):
            raise ValueError("base readback invalid")
        _checked_base(audit, report)
        if audit.get("id") != str(audit_id):
            raise ValueError("base audit ID mismatch")
        url, source_hash = audit["source_url"], audit["source_hash"]

        def inspect() -> str:
            return _source_result(url, source_hash)

        def validate(leader_result: gl.vm.Result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            return leader_result.calldata in ("MEETS_BASELINE", "FAIL", "UNVERIFIABLE") and leader_result.calldata == inspect()

        outcome = gl.vm.run_nondet_unsafe(inspect, validate)
        if outcome not in ("MEETS_BASELINE", "FAIL", "UNVERIFIABLE"):
            raise ValueError("invalid consensus correction")
        composite = _composite(report, outcome)
        patch = {
            "audit_id": str(audit_id), "base_registry": self.base_registry,
            "base_report_sha256": report["report_sha256"],
            "created_at": gl.message_raw["datetime"], "outcome": outcome,
            "report_sha256": composite["report_sha256"],
            "source_hash": source_hash, "source_url": url,
        }
        self.patches[audit_id] = _json(patch)
        self.reports[audit_id] = _json(composite)
        return composite["report_sha256"]

    @gl.public.view
    def get_patch(self, audit_id: u64) -> str:
        return self.patches[audit_id] if audit_id in self.patches else ""

    @gl.public.view
    def get_report(self, audit_id: u64) -> str:
        return self.reports[audit_id] if audit_id in self.reports else ""
