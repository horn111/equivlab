# Verification evidence

This ledger distinguishes completed local checks from deployment claims. A
`PENDING` value means the action has not happened and must not be presented as
evidence.

## Local verification

| Gate | Result | Boundary |
| --- | --- | --- |
| Dependency-free Python suite | `68 passed, 1 skipped` on 2026-08-25 | Analyzer, API boundary, contract stub; direct-mode module skips when unavailable |
| GenLayer direct-mode suite | `7 passed` on 2026-08-25 | Official GenVM runner with mocked web/model responses |
| Frontend unit/integration suite | `18 passed` on 2026-08-25 | Browser-local behavior, mocked SDK clients, and the wallet-to-authoritative-readback lifecycle |
| Production frontend build | Passed on 2026-08-25 | TypeScript and Vite production compilation |
| npm dependency audit | `0 vulnerabilities` on 2026-08-25 | Published npm dependency advisories |
| Impeccable static detector | `0 findings` on 2026-08-25 | `web/src` source scan with the checked-in design system |
| Desktop/mobile browser pass | Passed at 1440×1000 and 390×844 on 2026-08-25 | Local dev server, visible rule feedback, fixture switching, analysis result, configured/unconfigured registry boundary, and horizontal overflow |

Local success does not establish live-network behavior, formal verification, or
a security guarantee.

## Release identity

| Evidence | Value |
| --- | --- |
| GitHub repository | PENDING |
| Release commit (40 characters) | PENDING |
| License selected by repository owner | PENDING |
| Vercel production URL | PENDING |
| GenLayer network | `testnetBradbury` (target, not yet evidence) |
| Registry contract address | PENDING |
| Registry deployment transaction | PENDING |
| Successful audit transaction | PENDING |
| Authoritative readback checked | PENDING |

## Required live fixture results

| Fixture | Expected result | Live transaction/readback |
| --- | --- | --- |
| Permissionless tip jar | `FAIL`: `AUTH-01`, `VALUE-01` | PENDING |
| Schema-only validator | `FAIL`: `CONS-01`, `EVID-01` | PENDING |
| Hardened fact checker | `MEETS_BASELINE` | PENDING |
| Deliberate hash mismatch | `UNVERIFIABLE`: `SRC-01` | PENDING |
