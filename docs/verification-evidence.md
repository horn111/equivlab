# Verification evidence

This ledger distinguishes completed local checks from deployment claims. A
`PENDING` value means the action has not happened and must not be presented as
evidence.

## Local verification

| Gate | Result | Boundary |
| --- | --- | --- |
| Dependency-free Python suite | `68 passed, 1 skipped` on 2026-08-27 | Analyzer, API boundary, contract stub; direct-mode module skips when unavailable |
| GenLayer direct-mode suite | `7 passed` on 2026-08-27 | Official GenVM runner with mocked web/model responses |
| Frontend unit/integration suite | `18 passed` on 2026-08-27 | Browser-local behavior, mocked SDK clients, and the wallet-to-authoritative-readback lifecycle |
| Production frontend build | Passed on 2026-08-27 | TypeScript and Vite production compilation |
| npm dependency audit | `0 vulnerabilities` on 2026-08-25 | Published npm dependency advisories |
| Impeccable static detector | `0 findings` on 2026-08-25 | `web/src` source scan with the checked-in design system |
| Desktop/mobile browser pass | Passed at 1440×1000 and 390×844 on 2026-08-25 | Local dev server, visible rule feedback, fixture switching, analysis result, configured/unconfigured registry boundary, and horizontal overflow |

Local success does not establish live-network behavior, formal verification, or
a security guarantee.

## Release identity

| Evidence | Value |
| --- | --- |
| GitHub repository | <https://github.com/horn111/equivlab> |
| Published reference-fixture commit | `aef703943cef6a6d9c3f65545072711d78d44417` |
| Registry web-fetch fix commit | `6af02a2653591810b4f3dce4e7d4c118f651c239` |
| Web runtime/packaging commit | `66345fdefe96c7be7f63953021581b7eecdfe22d` |
| License selected by repository owner | [MIT](../LICENSE) |
| Vercel production URL | <https://equivlab.vercel.app> |
| GenLayer network | `testnetBradbury` |
| Registry contract address | `0x45a08F1516b2b54603bfAE87780e7F6f38d31F20` |
| Registry deployment transaction | `0xa79059bb43c10a389f39a4a348499e9b8e2f98ccce286be1b89b4117b7f4ff27` (`FINISHED_WITH_RETURN`, five validator votes `AGREE`) |
| Successful audit transaction | `0x87f61e50c88bce0e8848d8fcb71626af397d887da330a309437135ebd327d007` (`FINISHED_WITH_RETURN`, five validator votes `AGREE`) |
| Authoritative readback checked | Audit `0`; report `701f251620838d9f786fdb3d1816637842b44b89070efdf7670f163f4585bbba` |

## Required live fixture results

| Fixture | Expected result | Live transaction/readback |
| --- | --- | --- |
| Permissionless tip jar | `FAIL`: `AUTH-01`, `VALUE-01` | Confirmed by audit `0` at the deployed registry; source hash `bd15033156ca35ca4610accd7c7276b6ebdf7e3e74e245dcf504266f39ca3a5d` |
| Schema-only validator | `FAIL`: `CONS-01`, `EVID-01` | PENDING |
| Hardened fact checker | `MEETS_BASELINE` | PENDING |
| Deliberate hash mismatch | `UNVERIFIABLE`: `SRC-01` | PENDING |

## Rejected release candidate

Registry `0xC9D45F34213B8B0BD06aC89A5492747a0400F979` used
`gl.nondet.web.render()` for a static raw GitHub file. Bradbury could not
retrieve that source through the rendering path, so its diagnostic audit
correctly failed closed as `UNVERIFIABLE`. It is not the production registry.
The production contract uses the documented `gl.nondet.web.get()` response
body path and passed the live permissionless-tip-jar acceptance check above.
