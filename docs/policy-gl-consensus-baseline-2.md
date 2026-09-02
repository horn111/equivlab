# `gl-consensus-baseline-2` deterministic core

This policy evaluates inspectable source patterns in one canonical, source-pinned
Python Intelligent Contract revision. It issues `MEETS_BASELINE` only when the
file contains a recognizable `gl.Contract`, a public GenLayer entrypoint, and a
`run_nondet_unsafe` path reachable from a public write entrypoint. A plain Python
file, a decorated non-contract class, or a contract without a reachable consensus
path is `UNVERIFIABLE` for `CONS-01` instead of passing vacuously.

`MEETS_BASELINE` is neither formal verification nor a security guarantee. The
analyzer runs no semantic model and does not claim that a detected syntactic guard
enforces the intended business rule.

## Deterministic rules

| Rule | Deterministic acceptance condition |
|---|---|
| `SRC-01` | Canonical SHA-256 matches and the source URL is an HTTPS `raw.githubusercontent.com` URL containing a full 40-hex commit. |
| `CONS-01` | The source has recognizable GenLayer contract structure, a public-write-reachable consensus path, and every validator reaches a separate `gl.nondet.*` evaluation call. |
| `RESULT-01` | Every reachable validator has a blocking `isinstance(..., gl.vm.Result/Return)` guard for its leader-result parameter. |
| `BOUND-01` | A state write derived from model/consensus output has a preceding blocking enum/range comparison. |
| `AUTH-01` | Every public value-transfer call path has a preceding fail-closed sender-versus-state authority guard. |
| `VALUE-01` | Transfer amount is not caller/model controlled; an unguarded recipient is not caller controlled. |
| `EVID-01` | When a reachable leader observes `gl.nondet.web.*`, its validator independently reaches a web observation. |
| `PROMPT-01` | Prompt text derived from untrusted input contains an explicit data-not-instructions framing marker. |
| `URL-01` | Public URL inputs reaching web observation have blocking HTTPS, approved-host, length, and applicable duplicate checks. |
| `STATE-01` | State is not written before consensus or from a leader/validator callback. |
| `REPLAY-01` | Repeatable non-balance settlements have a terminal state guard and terminal write before transfer. |
| `TIME-01` | Public method parameters do not flow into authoritative time-named state fields. |

## Contract eligibility

- A recognized contract directly inherits `gl.Contract` and declares at least one
  `@gl.public.*` entrypoint.
- Consensus eligibility requires `gl.vm.run_nondet_unsafe` to be reachable from a
  public write or payable entrypoint through statically resolvable same-class calls.
- A dead helper containing a consensus call does not satisfy the eligibility gate.
- A failing rule still produces `FAIL` when another rule is `UNVERIFIABLE`. This
  preserves proven failures such as `AUTH-01` and `VALUE-01` on a deterministic
  transfer contract that has no consensus path.

## Known deterministic limits

- Call-path tracing resolves module functions, same-class `self.*` methods, and
  lexically nested functions. It does not resolve dynamic dispatch, reflection,
  monkey-patching, or imported aliases with runtime behavior.
- Authority detection recognizes fail-closed comparisons between sender-derived
  data and contract state. It does not decide whether the stored authority was
  initialized correctly or whether a permissionless invariant is economically safe.
- Consensus and evidence rules prove that an independent call path exists, not
  that it asks the same question or observes equivalent evidence.
- Prompt framing recognizes a fixed marker vocabulary. It cannot prove prompt-
  injection resistance or that surrounding instructions are effective.
- Bounds detection proves that a comparison precedes a model-derived state write.
  It does not prove that the selected bounds match the intended domain.
- Findings can contain false positives and false negatives. Direct-mode execution
  and validator disagreement tests remain separate verification layers.

## Status aggregation

- A proven failed rule produces `FAIL`, even if a different rule remains
  `UNVERIFIABLE`.
- Otherwise an unverifiable rule produces `UNVERIFIABLE`.
- Otherwise a warning produces `WARN`.
- Only an eligible GenLayer consensus contract with no non-passing rules receives
  `MEETS_BASELINE` for this named policy revision.

Consensus-relevant rule lists and findings are sorted. `report_sha256` is computed
over compact key-sorted JSON before the hash field is inserted.
