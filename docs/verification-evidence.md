# Verification evidence

This ledger separates reproducible local checks, public deployment facts, and
live GenLayer readback. None of these results is formal verification or a
security guarantee.

## Local verification

| Gate | Result | Boundary |
| --- | --- | --- |
| Dependency-free Python suite | `117 passed` on 2026-08-27 | Analyzer, API boundary, and contract stub; unrelated global pytest plugins disabled |
| GenLayer direct-mode suite | `7 passed` on 2026-08-27 | Official GenVM v0.2.16 runner with mocked web responses |
| Frontend unit/integration suite | `23 passed` on 2026-08-27 | Browser-local behavior, SDK clients, and wallet/readback lifecycle |
| Production frontend build | Passed on 2026-08-27 | TypeScript and Vite production compilation |
| npm dependency audit | `0 vulnerabilities` on 2026-08-27 | Published npm dependency advisories |
| Impeccable static detector | `0 findings` on 2026-08-27 | `web/src` source scan |
| Responsive browser pass | Passed at 1440×900, 1440×700, and 390×844 on 2026-08-27 | Fixture switching, local analysis, result focus, 44px targets, and horizontal overflow |
| Production browser E2E | Passed on 2026-08-27 | Pinned fetch → `/api/analyze` 200 → local `FAIL` → automatic source-matched audit `1` registry readback without wallet; UI states that finalization was not independently checked |
| Production accessibility | `0` WCAG A/AA violations on 2026-08-27 | axe-core 4.12.1; contrast remained incomplete where pseudo-element backgrounds prevented automated calculation |
| Production API observability | 200, `FAIL`, 2 ms application duration | Structured Vercel runtime log with request ID |

## Release identity

| Evidence | Value |
| --- | --- |
| GitHub repository | <https://github.com/horn111/equivlab> |
| Pinned fixture revision | `ce007240d1cbb1b7a789348b566cb50cea9b80e7` |
| Vercel production URL | <https://equivlab.vercel.app> |
| Vercel deployment | `dpl_FGBfdZ315QhgHAXfwatKBiBL7akM` (`READY`) |
| GenLayer network | `testnetBradbury` |
| Production registry | `0xB4818B0269DbA2B8F1F567ecB8c25967F2ba8599` |
| Registry deployment transaction | `0x4d0523f6633f52ad3d4e7b2e9d39efc1aa3f80ce931f126c43fd9e49848a5616` (`ACCEPTED`, `FINISHED_WITH_RETURN`) |
| Registry count | `4` consensus-accepted audit records |
| Edge abuse control | Published Vercel WAF rule: `/api/analyze`, 24 requests per 60 seconds per IP |

## Live fixture matrix

Every successful transaction below reached `ACCEPTED` and
`FINISHED_WITH_RETURN` with five validator votes `AGREE`. At the time this
ledger was written, the appeal window had not elapsed and
`finalization_timestamp` remained `0`; the UI does not label an existing record
as finalized without its transaction receipt.

| Audit | Fixture | Consensus-accepted registry result | Transaction | Report SHA-256 |
| --- | --- | --- | --- | --- |
| `0` | Hardened fact checker | `MEETS_BASELINE` | `0x9913bc7b99ed607310c2309a615fdf9da60087f207cc9d21748805bd82689ab8` | `caf756afa2c986e6cc4f4be54842f71c2358cd3f7cc7719b049ec8f4c2f74483` |
| `1` | Permissionless tip jar | `FAIL`: `AUTH-01`, `VALUE-01` | `0x6c88c2f02040fb01f5e9d079ad15d74726e71b12f1a059000dbd8749049e005e` | `8806ec4f5139e943fc3793a24fbb12fac6c7b2c1a45361b512d2675acde8fbcb` |
| `2` | Schema-only validator | `FAIL`: `CONS-01`, `EVID-01` | `0x9e8177798ae5aea997d4e056cfd63a3352e2a4fa6c1411c1791518d820578405` | `78491c153d6902a4c0a7130ead8a8e483cb2bd0de1094bb51991d051661029d3` |
| `3` | Deliberate hash mismatch | `UNVERIFIABLE`: all twelve rules | `0x512496274e230e1bc3e7885ede7a3eba13d9387c43f1a745f2109adcfffc2622` | `cc6c61b0fa7721b4115ca64ef8fc533e2db94f70830bfd87448de2aad8445b25` |

Pinned canonical hashes:

- hardened fact checker: `bc31552097a0c7c0a176faf884c528e997c52e759c26aa96095b792a276fdfc2`;
- permissionless tip jar: `bd15033156ca35ca4610accd7c7276b6ebdf7e3e74e245dcf504266f39ca3a5d`;
- schema-only validator: `d9d8f589765455bb30b56dba05ca8c7493d1656d30a26f6c23725ab675ef0e0a`;
- mismatch submission: sixty-four zeroes, which does not match the fetched tip-jar bytes.

## Superseded deployments

- `0x45a08F1516b2b54603bfAE87780e7F6f38d31F20` is the first successful live
  registry. It proved the tip-jar acceptance case but predates full source
  identity and challenge-history hardening.
- `0xBCE5427062A0252f27047814559a1cD43aC73c95` added the v2 identity model but
  retained a semantic model supplement. Bradbury leader timeouts and a false
  warning on the positive fixture made that path unsuitable for release.
- `0xC9D45F34213B8B0BD06aC89A5492747a0400F979` used
  `gl.nondet.web.render()` for a static raw GitHub file and correctly failed
  closed when Bradbury could not retrieve it through that path.

The production registry removes the semantic model dependency, uses independent
leader and validator `gl.nondet.web.get()` fetches, and compares only bounded,
deterministic decision fields before writing state.
