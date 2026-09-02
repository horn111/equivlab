"""Build the compact, schema-preserving GenLayer deployment source."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path

import python_minifier


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "contracts" / "consensus_safety_registry.py"
DEFAULT_OUTPUT = ROOT / "build" / "consensus_safety_registry.py"
MAX_DEPLOYMENT_BYTES = 36_000


def _contract_surface(source: str) -> tuple[tuple[object, ...], tuple[object, ...]]:
    tree = ast.parse(source)
    contract = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ConsensusSafetyRegistry"
    )
    fields = tuple(
        sorted(
            (node.target.id, ast.dump(node.annotation, include_attributes=False))
            for node in contract.body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        )
    )
    methods = []
    for node in contract.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = {ast.unparse(decorator) for decorator in node.decorator_list}
        if not any(name.startswith("gl.public.") for name in decorators):
            continue
        arguments = tuple(
            (argument.arg, ast.dump(argument.annotation, include_attributes=False) if argument.annotation else None)
            for argument in node.args.args
        )
        returns = ast.dump(node.returns, include_attributes=False) if node.returns else None
        methods.append((node.name, arguments, returns))
    return fields, tuple(sorted(methods))


def build_deployment_source(source: str) -> str:
    dependency_header = source.splitlines()[0]
    if not dependency_header.startswith('# { "Depends":'):
        raise ValueError("GenLayer dependency header must be the first source line.")

    compact = python_minifier.minify(
        source,
        filename=str(DEFAULT_SOURCE),
        remove_annotations=False,
        remove_literal_statements=True,
        rename_globals=False,
        rename_locals=True,
        preserve_shebang=False,
    )
    output = dependency_header + "\n" + compact.lstrip() + "\n"
    if _contract_surface(output) != _contract_surface(source):
        raise ValueError("Deployment build changed the contract storage or method schema.")
    size = len(output.encode("utf-8"))
    if size > MAX_DEPLOYMENT_BYTES:
        raise ValueError(f"Deployment source is {size} bytes; limit is {MAX_DEPLOYMENT_BYTES}.")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    source = args.source.read_text(encoding="utf-8")
    output = build_deployment_source(source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(output.encode("utf-8")).hexdigest()
    print(f"Built {args.output} ({len(output.encode('utf-8'))} bytes, sha256 {digest})")


if __name__ == "__main__":
    main()
