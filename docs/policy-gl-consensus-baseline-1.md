# `gl-consensus-baseline-1` deterministic core

This policy evaluates inspectable source patterns in one canonical, source-pinned
Python Intelligent Contract revision. A `MEETS_BASELINE` result is neither formal
verification nor a security guarantee. Phase 2 runs no semantic model and does
not claim that a detected syntactic guard enforces the intended business rule.

## Deterministic rules

| Rule | Deterministic acceptance condition |
|---|---|
| `SRC-01` | Canonical SHA-256 matches and the source URL is an HTTPS `raw.githubusercontent.com` URL containing a full 40-hex commit. |
| `CONS-01` | Every `run_nondet_unsafe` validator reaches a separate `gl.nondet.*` evaluation call. |
| `RESULT-01` | Every validator has a blocking `isinstance(..., gl.vm.Result/Return)` guard for its leader-result parameter. |
| `BOUND-01` | A state write derived from model/consensus output has a preceding blocking enum/range comparison. |
| `AUTH-01` | Every public value-transfer call path has a preceding fail-closed sender-versus-state authority guard. |
| `VALUE-01` | Transfer amount is not caller/model controlled; an unguarded recipient is not caller controlled. |
| `EVID-01` | When the leader reaches `gl.nondet.web.*`, the validator independently reaches a web observation. |
| `PROMPT-01` | Prompt text derived from untrusted input contains an explicit data-not-instructions framing marker. |
| `URL-01` | Public URL inputs reaching web observation have blocking HTTPS, approved-host, length, and applicable duplicate checks. |
| `STATE-01` | State is not written before consensus or from a leader/validator callback. |
| `REPLAY-01` | Repeatable non-balance settlements have a terminal state guard and terminal write before transfer. |
| `TIME-01` | Public method parameters do not flow into authoritative time-named state fields. |

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
- Balance-based withdrawals are exempt from `REPLAY-01` because the transferred
  balance is consumed by the transfer. `AUTH-01` and `VALUE-01` still apply.
- Findings can contain false positives and false negatives. Semantic supplements,
  direct-mode execution, and validator disagreement tests belong to later phases.

## Status aggregation

- `UNVERIFIABLE` takes precedence when source identity or parse facts cannot be established.
- Otherwise any failed rule produces `FAIL`.
- Otherwise any warning produces `WARN`.
- Otherwise the report says `MEETS_BASELINE` for this named policy revision only.

Consensus-relevant rule lists and findings are sorted. `report_sha256` is computed
over compact key-sorted JSON before the hash field is inserted.
