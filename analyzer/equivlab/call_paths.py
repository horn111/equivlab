"""Call graph traversal for public value-transfer and consensus paths."""

from __future__ import annotations

from dataclasses import dataclass

from .ast_index import AnalysisLimitExceeded, AstIndex, StateWrite, TransferSite


MAX_CALL_GRAPH_STEPS = 20_000
MAX_TRANSFER_PATHS = 4_096


@dataclass(frozen=True)
class TransferPath:
    root: str
    functions: tuple[str, ...]
    call_lines: tuple[int, ...]
    transfer: TransferSite
    guarded: bool


@dataclass(frozen=True, order=True)
class StateOrderFailure:
    root: str
    function: str
    write: StateWrite


class CallPathAnalyzer:
    def __init__(self, index: AstIndex):
        self.index = index
        self._steps = 0

    def _consume(self) -> None:
        self._steps += 1
        if self._steps > MAX_CALL_GRAPH_STEPS:
            raise AnalysisLimitExceeded("call-graph analysis exceeded the deterministic work budget")

    def transfer_paths(self) -> list[TransferPath]:
        cached = self.index.analysis_cache.get("transfer_paths")
        if isinstance(cached, tuple):
            return list(cached)
        paths: list[TransferPath] = []
        for root in self.index.public_write_functions:
            self._walk_transfers(root.qualname, root.qualname, (root.qualname,), (), False, frozenset(), paths)
        result = sorted(paths, key=lambda item: (item.root, item.transfer.line, item.functions))
        self.index.analysis_cache["transfer_paths"] = tuple(result)
        return result

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
        self._consume()
        if current in seen:
            return
        info = self.index.functions[current]
        next_seen = seen | {current}

        for transfer in info.transfers:
            guarded_here = guarded_before_entry or any(guard.line < transfer.line for guard in info.authority_guards)
            output.append(TransferPath(root, functions, call_lines, transfer, guarded_here))
            if len(output) > MAX_TRANSFER_PATHS:
                raise AnalysisLimitExceeded("transfer-path analysis exceeded the deterministic path budget")

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
        return any(self.index.functions[name].nondeterministic_lines for name in self.reachable_functions(function_name))

    def reaches_web_observation(self, function_name: str) -> bool:
        return any(self.index.functions[name].web_observation_lines for name in self.reachable_functions(function_name))

    def reaches_consensus(self, function_name: str) -> bool:
        return any(self.index.functions[name].consensus_calls for name in self.reachable_functions(function_name))

    def reachable_functions(self, function_name: str) -> tuple[str, ...]:
        cache_key = f"reachable:{function_name}"
        cached = self.index.analysis_cache.get(cache_key)
        if isinstance(cached, tuple):
            return cached
        output: set[str] = set()

        def walk(current: str) -> None:
            self._consume()
            if current in output or current not in self.index.functions:
                return
            output.add(current)
            info = self.index.functions[current]
            for call in info.calls:
                target = self.index.resolve_call(info, call.name)
                if target is not None:
                    walk(target)

        walk(function_name)
        result = tuple(sorted(output))
        self.index.analysis_cache[cache_key] = result
        return result

    def state_order_failures(self) -> tuple[StateOrderFailure, ...]:
        cached = self.index.analysis_cache.get("state_order_failures")
        if isinstance(cached, tuple):
            return cached
        failures: set[StateOrderFailure] = set()
        for root in self.index.public_write_functions:
            if not self.reaches_consensus(root.qualname):
                continue
            self._walk_state_order(root.qualname, root.qualname, False, frozenset(), failures)
        result = tuple(sorted(failures))
        self.index.analysis_cache["state_order_failures"] = result
        return result

    def _walk_state_order(
        self,
        root: str,
        current: str,
        consensus_seen: bool,
        seen: frozenset[str],
        failures: set[StateOrderFailure],
    ) -> bool:
        self._consume()
        if current in seen or current not in self.index.functions:
            return consensus_seen
        info = self.index.functions[current]
        next_seen = seen | {current}
        events: list[tuple[int, int, object]] = []
        events.extend((write.line, 0, write) for write in info.state_writes)
        events.extend((call.line, 1, call) for call in info.calls)
        events.extend((call.line, 2, call) for call in info.consensus_calls)
        for _line, kind, event in sorted(events, key=lambda item: (item[0], item[1])):
            if kind == 0:
                write = event
                if isinstance(write, StateWrite) and not consensus_seen:
                    failures.add(StateOrderFailure(root, current, write))
                continue
            if kind == 2:
                consensus_seen = True
                continue
            call = event
            target = self.index.resolve_call(info, call.name)
            if target is not None:
                consensus_seen = self._walk_state_order(
                    root,
                    target,
                    consensus_seen,
                    next_seen,
                    failures,
                )
        return consensus_seen
