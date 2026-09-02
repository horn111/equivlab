# Contract verification status

## Implemented contract behavior

`contracts/consensus_safety_registry.py` is a single source-deployable GenLayer
contract. It provides:

- source URL, canonical SHA-256, and policy binding;
- independent leader and validator source fetches;
- deterministic AST and bounded call-path findings with no semantic model dependency;
- fail-closed `UNVERIFIABLE` results for fetch, hash, and parse failure;
- fail-closed contract-structure and public consensus-path eligibility before `MEETS_BASELINE`;
- immutable JSON reports with stable `report_sha256`;
- duplicate prevention, permissionless challenge records, and explicit supersession history;
- `request_audit`, `get_audit`, `get_report`, `get_latest`, `challenge`, and `count`.

Validator equality covers only observation schema, policy, source hash, status,
severity, and sorted failed/warning/unverifiable rule IDs. Narrative text is not
part of the equality boundary.

`MEETS_BASELINE` is not formal verification or a security guarantee.

## Test layers

The dependency-free suite imports the actual contract source with a deterministic
GenLayer runtime stub. It covers `MEETS_BASELINE`, `WARN`, `FAIL`, and
`UNVERIFIABLE`; fetch/hash failure; leader/validator source disagreement before
storage writes; duplicate audit; challenge; supersession; latest lookup; report
hashing; adversarial guard polarity; helper-mediated transfer and consensus
paths; deterministic resource limits; and retrieved/submitted provenance.

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest
```

Current dependency-free result: `157 passed`; the direct-mode module is skipped
when `genlayer-test` is unavailable.

The genuine GenLayer direct-mode suite contains eight additional tests:

```powershell
python -m venv .venv-direct
.venv-direct\Scripts\python.exe -m pip install -r requirements-direct.txt
.venv-direct\Scripts\python.exe -m pytest tests/direct -v
```

Verified again on 2026-09-02 with `genlayer-test==0.29.2`, `genlayer-py==0.16.3`,
Python 3.12.0, and the official GenVM v0.2.16 universal artifact:

- artifact size: `216630904` bytes;
- artifact SHA-256: `4f0b358ec98ec148be9b95cdfb0f0e1a6cbe64da0194fdfac3fffc6f5d1d93e2`;
- archive table read successfully: 25 entries;
- direct-mode result: `8 passed`;

`genlayer-test==0.29.2` retains the SDK's single-contract registration between
deployments and keeps a duplicated stdin handle open on Windows. The direct test
adapter resets only that SDK registration before each deployment and tolerates
only the resulting Windows `PermissionError` while unlinking the runner's own
temporary stdin file. The dependency-free contract stub restores any pre-existing
`genlayer` module after loading, so the combined suite is order-independent.

These are local direct-runner results with mocked web responses. They
do not establish live-network behavior, formal verification, or a security
guarantee.

## Self-audit

The analyzer reports `MEETS_BASELINE` for the registry source against all
twelve deterministic cores. This is a regression signal only and does not replace
direct-mode execution or manual review.
