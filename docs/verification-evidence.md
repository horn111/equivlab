# Verification evidence

This ledger separates reproducible local checks, public deployment facts, and
live GenLayer readback. None of these results is formal verification or a
security guarantee.

## Local verification

| Gate | Result | Boundary |
| --- | --- | --- |
| Dependency-free Python suite | `157 passed` on 2026-09-02 | Baseline-3 analyzer, API boundary, guard polarity, bounded work, contract eligibility, local/on-chain parity, and contract stub; unrelated global pytest plugins disabled |
| GenLayer direct-mode suite | `8 passed` on 2026-09-02 | Official GenVM v0.2.16 runner with mocked web responses, including non-contract and missing-consensus outcomes |
| Frontend unit/integration suite | `29 passed` on 2026-09-02 | Browser-local behavior, mixed `FAIL`/`UNVERIFIABLE` reports, SDK clients, EIP-1193 switching, and wallet/readback lifecycle |
| Production frontend build | Passed on 2026-09-02 | TypeScript and Vite production compilation |
| npm dependency audit | `0 vulnerabilities` on 2026-09-02 | Published npm dependency advisories |
| Impeccable static detector | `0 findings` on 2026-09-02 | Reviewer-facing `web/src` source and style scan |
| Responsive browser pass | Passed at 1280×720 and 390×844 on 2026-09-02 | Default pinned retrieval, explicit preview mode, one-click non-contract outcome, visible rule-selection evidence, 44px targets, console errors, and horizontal overflow |
| Production browser E2E | Passed on 2026-09-02 | Baseline-3 pinned fetch → `/api/analyze` 200 → all four local outcomes → exact source-matched registry audits `0`–`3` without wallet; no console errors or framework overlay |
| Wallet connection browser test | Passed on 2026-08-27 | Simulated injected EIP-1193 provider → account authorization → Bradbury switch fallback → Bradbury network addition; no signature or transaction was simulated |
| Production accessibility | `0` WCAG A/AA violations on 2026-09-02 | axe-core 4.12.1 after result-region semantics fix; contrast remained incomplete where pseudo-element backgrounds prevented automated calculation |
| Production API and registry readback | Passed on 2026-09-02 | Production reproduced the pinned baseline-3 commit, registry address, four report hashes, and expected outcome matrix |

## Baseline-3 release boundary

The source tree, production analyzer, and Bradbury registry use
`gl-consensus-baseline-3` and `equivlab-report-v2`. The release identity below
binds the deployed contract, analyzed fixture revision, production deployment,
and four source-pinned audits. Baseline-1 and baseline-2 records remain
immutable historical evidence.

## Release identity

| Evidence | Value |
| --- | --- |
| GitHub repository | <https://github.com/horn111/equivlab> |
| Pinned fixture revision | `e60cae9cbc15a5f5c95fc27daac658f60c99ea99` |
| Vercel production URL | <https://equivlab.vercel.app> |
| Vercel deployment | `dpl_6ReHyHa3quJTju6paL2ey526azXV` (`READY`, production) |
| GenLayer network | `testnetBradbury` |
| Production registry | `0xab90cA3d5d8E9341c1681475e50343C423AA903f` |
| Compact deployment source | `34,526` bytes; SHA-256 `31e0625280e4aad25a15ca74aa85bfc3b4ef00c18473a49e10443df27efad5aa`; finalized on-chain code readback matched both values |
| Registry deployment transaction | [`0x085d…9d13`](https://explorer-bradbury.genlayer.com/tx/0x085d3b4252a669d80ff5cd957710d84fe8721e12ff57e5a41f0fae5ab4eb9d13) (`FINALIZED`, `FINISHED_WITH_RETURN`) |
| Registry count | `4` finalized baseline-3 audit records |
| Historical baseline-1 registry | `0xB4818B0269DbA2B8F1F567ecB8c25967F2ba8599` |
| Edge abuse control | Published Vercel WAF rule: `/api/analyze`, 24 requests per 60 seconds per IP |

## Live baseline-3 fixture matrix

Every transaction below reached `FINALIZED` and `FINISHED_WITH_RETURN` with
five validator votes `AGREE`. Registry readback reproduced the exact source
URL, canonical hash, policy, and report. Finalization status was independently
queried through Bradbury's `gen_getTransactionStatus` endpoint after each
appeal window elapsed.

| Audit | Source | Finalized registry result | Transaction | Report SHA-256 |
| --- | --- | --- | --- | --- |
| `0` | Hardened fact checker | `MEETS_BASELINE` | [`0x8e4b…ab3a`](https://explorer-bradbury.genlayer.com/tx/0x8e4b3d32346f2643c6200c9fc0278dff514fcc3baca8b9dd2d462c8a8235ab3a) | `af7d8f937361766286e55c17ea96709f37519ac4103d5edd42756c189f77af62` |
| `1` | Permissionless tip jar | `FAIL`: `AUTH-01`, `VALUE-01`; `CONS-01` is `UNVERIFIABLE` | [`0x3cd5…6e86`](https://explorer-bradbury.genlayer.com/tx/0x3cd5946d6ce8f59e5dbc80a071c3d7c005d67231f73d1a0e97a644faaeb06e86) | `f5b36526e4081d3e7b62325376b1c289001b29266931930b717f0d9e2569891b` |
| `2` | Schema-only validator | `FAIL`: `CONS-01`, `EVID-01` | [`0xfa89…28b9`](https://explorer-bradbury.genlayer.com/tx/0xfa89e9d952fb6ad62517569a31e04f5a32b8b70d8b7e0e0997566e1acce428b9) | `82f916d1db32716b84108ea5d922e92b3c3b6b1a8691c9d4a8bfcf5c42711420` |
| `3` | Plain Python non-contract | `UNVERIFIABLE`: eleven AST rules; `SRC-01` source identity established | [`0x604d…21a9`](https://explorer-bradbury.genlayer.com/tx/0x604dc60c7fd8137031c6a1dcf1290a987391060fdb6bd34f8f7032e6a45221a9) | `6ecb226c40dec0f6e2ccc66a2bcb30e7376af64f822044e38a929a5d210053d7` |

Pinned baseline-3 canonical hashes:

- hardened fact checker: `bc31552097a0c7c0a176faf884c528e997c52e759c26aa96095b792a276fdfc2`;
- permissionless tip jar: `bd15033156ca35ca4610accd7c7276b6ebdf7e3e74e245dcf504266f39ca3a5d`;
- schema-only validator: `d9d8f589765455bb30b56dba05ca8c7493d1656d30a26f6c23725ab675ef0e0a`;
- plain Python non-contract: `9402645188f81481134b53a673c2fc5d2dde54d834fd4b3b5fbcfee2e74355ac`.

## Historical baseline-2 fixture matrix

Every transaction below reached `ACCEPTED` and `FINISHED_WITH_RETURN`; the
registry readback reproduced the exact source URL, canonical hash, policy, and
report. Their `finalization_timestamp` values were still `0` when this ledger
was updated, so the evidence is consensus-accepted rather than independently
finalized.

| Audit | Source | Consensus-accepted registry result | Transaction | Report SHA-256 |
| --- | --- | --- | --- | --- |
| `0` | Hardened fact checker | `MEETS_BASELINE` | `0xfd222ad1af6c73dfa391e9602fc37a55ea22cd2e7a28873d2424a8b04872d302` | `f6b8e8bdd265bf5bfdbfb25ee2e47ff6e45975ea7f34cde4d19df0c2f0f40bf8` |
| `1` | Permissionless tip jar | `FAIL`: `AUTH-01`, `VALUE-01`; `CONS-01` is `UNVERIFIABLE` | `0x82bdebc3ede90b458aa45a9943e36b40e8a14b09817d100c5e5edba0dad62711` | `e73c02d40d4f923f141627d61945b1461f1fef31cc9e0fe987c5ae5841ee2e1d` |
| `2` | Schema-only validator | `FAIL`: `CONS-01`, `EVID-01` | `0x1cccaa9b9f09eea70f66975b5db12a53c4ed02e6fef15a4d8629ffe1e9e10007` | `046afe942d2233ee9e10bb209787b65edaa65babddfb7301189e0d0b318a66cd` |
| `3` | Plain Python non-contract | `UNVERIFIABLE`: eleven AST rules; `SRC-01` source identity established | `0x66a27589d5b488d1a551dbae1eb861d4dc88975fc9c67c7eda8b0da4e8fd36a9` | `6e8c45a027a5a53544ef797449c5f1da4bd672fce9662403cf8841778f4985c0` |

Pinned baseline-2 canonical hashes:

- hardened fact checker: `bc31552097a0c7c0a176faf884c528e997c52e759c26aa96095b792a276fdfc2`;
- permissionless tip jar: `bd15033156ca35ca4610accd7c7276b6ebdf7e3e74e245dcf504266f39ca3a5d`;
- schema-only validator: `d9d8f589765455bb30b56dba05ca8c7493d1656d30a26f6c23725ab675ef0e0a`;
- plain Python non-contract: `9402645188f81481134b53a673c2fc5d2dde54d834fd4b3b5fbcfee2e74355ac`.

## Historical baseline-1 fixture matrix

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
- mismatch request: sixty-four zeroes, which does not match the fetched tip-jar bytes.
