# `gl-consensus-baseline-3` deterministic core

Baseline 3 is the active policy implemented by this revision. It evaluates one
canonical, source-pinned Python Intelligent Contract file with twelve bounded AST
and call-path rules. `MEETS_BASELINE` is neither formal verification nor a
security guarantee.

## What changed from baseline 2

- Guard rules now check rejection direction and require a fail-closed branch;
  decorative, inverted, nested, and unreachable checks do not satisfy
  `RESULT-01`, `BOUND-01`, `URL-01`, or `REPLAY-01`.
- `STATE-01` and value-transfer rules follow statically resolvable same-class
  helper calls from public write entrypoints.
- AST, dependency, call-graph, transfer-path, and source-size work is bounded.
  Exceeding a limit produces `UNVERIFIABLE` instead of an optimistic pass.
- The report schema is `equivlab-report-v2`. Its hashed `source` object includes
  the provenance mode. Bytes supplied by a caller can still be analyzed, but
  `SRC-01` remains `UNVERIFIABLE` until the server retrieves the exact pinned URL.
- Canonical source URLs use exact HTTPS `raw.githubusercontent.com` identity, a
  lowercase 40-hex commit, and no credentials, port, query, fragment, encoding,
  doubled path separators, or trailing slash.

Baseline 2 remains published as historical policy documentation. Existing
baseline-2 registry records are not reinterpreted under baseline 3.

## Deterministic rules

| Rule | Deterministic acceptance condition |
|---|---|
| `SRC-01` | Retrieved canonical bytes match the submitted SHA-256 and an exact commit-pinned raw GitHub URL. Submitted-preview provenance cannot pass this rule. |
| `CONS-01` | Recognizable GenLayer contract structure has a bounded public-write-reachable consensus path and each validator reaches a separate `gl.nondet.*` evaluation. |
| `RESULT-01` | Each reachable validator rejects a non-`gl.vm.Return` outcome before using its payload. |
| `BOUND-01` | Model-derived state writes have a preceding fail-closed enum/range rejection. |
| `AUTH-01` | Each bounded public value-transfer path has a preceding sender-versus-state authority guard. |
| `VALUE-01` | Transfer amounts are not caller/model controlled; unguarded recipients are not caller controlled. |
| `EVID-01` | A validator independently re-observes external evidence used by its leader. |
| `PROMPT-01` | Untrusted prompt inputs have an explicit data-not-instructions framing marker. |
| `URL-01` | Public URL input is rejected unless it has the required scheme, host, length, and applicable duplicate policy. |
| `STATE-01` | No state write is reachable before consensus, including through helpers, or from a consensus callback. |
| `REPLAY-01` | A repeatable non-balance settlement path has a preceding terminal guard and terminal state write. |
| `TIME-01` | Public parameters do not flow into authoritative time-named state fields. |

## Resource limits

The policy accepts at most 100,000 canonical UTF-8 source bytes, 20,000 AST
nodes, 20,000 call-graph steps, 100,000 dependency-resolution steps, and 4,096
transfer paths. These are analysis boundaries, not statements about contract
runtime cost.

## Known limits

- Static traversal resolves direct module functions, lexical functions, and
  same-class calls. Dynamic dispatch, reflection, monkey-patching, and runtime
  imports remain outside the deterministic boundary.
- Syntactic authority checks do not establish that the stored owner or role was
  initialized correctly.
- Independent validator execution does not prove semantic equivalence between
  leader and validator questions or evidence.
- Fixed prompt-framing markers do not prove prompt-injection resistance.
- Findings may contain false positives and false negatives. Direct GenVM tests,
  transaction receipts, and registry readback remain separate evidence layers.

## Status aggregation

A proven rule failure produces `FAIL`, even if another rule is
`UNVERIFIABLE`. Otherwise `UNVERIFIABLE` outranks `WARN`. Only an eligible,
independently retrieved GenLayer consensus contract with no non-passing rule
receives `MEETS_BASELINE` under this named policy revision.
