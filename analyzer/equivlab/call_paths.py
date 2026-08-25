"""Call graph traversal for public value-transfer and consensus paths."""

from __future__ import annotations

from dataclasses import dataclass

from .ast_index import AstIndex, TransferSite


@dataclass(frozen=True)
class TransferPath:
    root: str
    functions: tuple[str, ...]
    call_lines: tuple[int, ...]
    transfer: TransferSite
    guarded: bool


class CallPathAnalyzer:
    def __init__(self, index: AstIndex):
        self.index = index

    def transfer_paths(self) -> list[TransferPath]:
        paths: list[TransferPath] = []
        for root in self.index.public_write_functions:
            self._walk_transfers(root.qualname, root.qualname, (root.qualname,), (), False, frozenset(), paths)
        return sorted(paths, key=lambda item: (item.root, item.transfer.line, item.functions))

    def _walk_transfers(
        self,
        root: str,
        current: str,
        functions: tuple[str, ...],
        call_lines: tuple[int, ...],
        guarded_before_entry: bool,
        seen: frozenset[str],
        output: list[TransferPath],
    ) -> None:
        if current in seen:
            return
        info = self.index.functions[current]
        next_seen = seen | {current}

        for transfer in info.transfers:
            guarded_here = guarded_before_entry or any(guard.line < transfer.line for guard in info.authority_guards)
            output.append(TransferPath(root, functions, call_lines, transfer, guarded_here))

        for call in info.calls:
            target = self.index.resolve_call(info, call.name)
            if target is None or target in next_seen:
                continue
            guarded_at_call = guarded_before_entry or any(guard.line < call.line for guard in info.authority_guards)
            self._walk_transfers(
                root,
                target,
                functions + (target,),
                call_lines + (call.line,),
                guarded_at_call,
                next_seen,
                output,
            )

    def reaches_nondeterminism(self, function_name: str) -> bool:
        return self._reaches_nondeterminism(function_name, frozenset())

    def _reaches_nondeterminism(self, function_name: str, seen: frozenset[str]) -> bool:
        if function_name in seen:
            return False
        info = self.index.functions.get(function_name)
        if info is None:
            return False
        if info.nondeterministic_lines:
            return True
        next_seen = seen | {function_name}
        for call in info.calls:
            target = self.index.resolve_call(info, call.name)
            if target is not None and self._reaches_nondeterminism(target, next_seen):
                return True
        return False

    def reaches_web_observation(self, function_name: str) -> bool:
        return self._reaches_web_observation(function_name, frozenset())

    def _reaches_web_observation(self, function_name: str, seen: frozenset[str]) -> bool:
        if function_name in seen:
            return False
        info = self.index.functions.get(function_name)
        if info is None:
            return False
        if info.web_observation_lines:
            return True
        next_seen = seen | {function_name}
        for call in info.calls:
            target = self.index.resolve_call(info, call.name)
            if target is not None and self._reaches_web_observation(target, next_seen):
                return True
        return False

    def reachable_functions(self, function_name: str) -> tuple[str, ...]:
        output: set[str] = set()

        def walk(current: str) -> None:
            if current in output or current not in self.index.functions:
                return
            output.add(current)
            info = self.index.functions[current]
            for call in info.calls:
                target = self.index.resolve_call(info, call.name)
                if target is not None:
                    walk(target)

        walk(function_name)
        return tuple(sorted(output))
