# Deployment runbook

This runbook separates reproducible local checks from external deployment
evidence. Do not replace pending fields with guessed addresses, hashes, or URLs.

## 1. Publish one exact Git revision

Create the GitHub repository, push the reviewed `main` branch, then record the
full 40-character commit hash. The bundled reference cards use that exact
revision in production.

Required Vite values:

```text
VITE_DEMO_REPOSITORY=<owner>/<repository>
VITE_DEMO_COMMIT=<full-40-character-commit>
```

Verify that all four raw URLs return the committed files:

```text
https://raw.githubusercontent.com/<owner>/<repository>/<commit>/fixtures/backdoored_tip_jar/contract.py
https://raw.githubusercontent.com/<owner>/<repository>/<commit>/fixtures/schema_only_fact_checker/contract.py
https://raw.githubusercontent.com/<owner>/<repository>/<commit>/fixtures/hardened_fact_checker/contract.py
https://raw.githubusercontent.com/<owner>/<repository>/<commit>/analyzer/equivlab/canonicalize.py
```

Never use `main`, another branch name, or a shortened hash as source identity.

## 2. Deploy the registry to GenLayer Bradbury

Build the deterministic compact registry source first. The build compares the
storage and public method signatures at the Python AST level, retains type
annotations, and fails if the output exceeds the configured byte ceiling:

```powershell
python -m pip install -r requirements-deploy.txt
python tools/build_deployment_contract.py
```

The readable source remains `contracts/consensus_safety_registry.py`; the
generated `build/consensus_safety_registry.py` is ignored and reproducible from
the exact Git revision. Record the printed build SHA-256 with the release
evidence.

Install and authenticate the current GenLayer CLI, select Bradbury, and deploy
the compact source contract:

```powershell
genlayer network testnet-bradbury
genlayer deploy --contract build/consensus_safety_registry.py
```

Save the deployment transaction hash and the returned contract address. Confirm
the transaction in the Bradbury explorer before configuring the frontend. The
official CLI workflow and current network setup are documented by GenLayer:

- <https://docs.genlayer.com/developers/intelligent-contracts/deploying/cli-deployment>
- <https://docs.genlayer.com/developers/intelligent-contracts/deploying/network-configuration>

As of 2026-09-27, the updated compact registry source is 35,768 bytes and
Bradbury estimates 28,820,129 gas for deployment. The RPC rejects signed
transactions with 29,900,000 gas as `gas limit too high` before acceptance.
GenLayer tracks a related [Bradbury deployment ceiling issue](https://github.com/genlayerlabs/genlayer-cli/issues/419).
Bradbury's `gen_getContractSchema` also rejects this new compact build, despite
the local AST surface check. It is not a deployable release artifact as-is.
Do not lower the signed gas below the network estimate or configure a new
registry address until the chain accepts a deployment and returns a contract
address with successful execution and schema readback. The source-size and AST
checks are not guarantees of network deployability.

Until that ceiling changes, baseline 3 keeps the original registry immutable
and uses `contracts/prompt_01_overlay.py` for a separate, consensus-backed
PROMPT-01 correction. Deploy its **readable source**, passing the baseline-3
registry address as an address argument:

```powershell
genlayer deploy --contract contracts/prompt_01_overlay.py --args 0xab90cA3d5d8E9341c1681475e50343C423AA903f
genlayer schema <overlay-address>
```

Check the deployment receipt's `txExecutionResultName` as well as its status;
the CLI can print a success banner for a transaction whose GenVM execution
failed. Do not deploy the minified overlay: the current Bradbury schema service
rejects that generated form. Once the readable deployment is finalized, invoke
`reconcile` for an affected audit ID. This submits a second GenLayer transaction,
retrieves the exact commit-pinned source through consensus, changes only
PROMPT-01 in a composite report, and leaves the base registry report unchanged.
Check the correction receipt and `get_patch`/`get_report` before publishing the
overlay address.

## 3. Configure and deploy Vercel

Use the repository's `equivlab` directory as the Vercel project root. The checked-in
`vercel.json` builds `web/dist` and exposes the Python analyzer at `/api/analyze`.

Set these production environment variables:

```text
VITE_NETWORK_NAME=testnetBradbury
VITE_REGISTRY_ADDRESS=<deployed-0x-address>
VITE_PROMPT_OVERLAY_ADDRESS=<finalized-overlay-0x-address>
VITE_GENLAYER_RPC_URL=https://rpc-bradbury.genlayer.com
VITE_EXPLORER_BASE_URL=https://explorer-bradbury.genlayer.com
VITE_DEMO_REPOSITORY=<owner>/<repository>
VITE_DEMO_COMMIT=<full-40-character-commit>
```

The RPC and explorer values may be omitted to use the values shipped by the
installed `genlayer-js` chain definition. Keeping them explicit makes the release
configuration reviewable.

Do not set `VITE_PROMPT_OVERLAY_ADDRESS` to a deployment that merely reached
`ACCEPTED`. Finalize and source-check at least one correction transaction first.

Baseline-3 production configuration (base registry and fixtures from 2026-09-02;
finalized PROMPT-01 overlay added 2026-09-27):

```text
VITE_NETWORK_NAME=testnetBradbury
VITE_REGISTRY_ADDRESS=0xab90cA3d5d8E9341c1681475e50343C423AA903f
VITE_PROMPT_OVERLAY_ADDRESS=0xd1197fDF969dA07018206ad4A13e8414578D57d7
VITE_DEMO_REPOSITORY=horn111/equivlab
VITE_DEMO_COMMIT=e60cae9cbc15a5f5c95fc27daac658f60c99ea99
```

Historical production release configuration for baseline 2 on 2026-09-02:

```text
VITE_NETWORK_NAME=testnetBradbury
VITE_REGISTRY_ADDRESS=0xb3DC5368F543b910A44fE42714077c7B8b1B4237
VITE_DEMO_REPOSITORY=horn111/equivlab
VITE_DEMO_COMMIT=ea9f1459da5f71f1f22e4e4fd41205431f97a6a6
```

Do not reuse the baseline-2 registry address for baseline 3. Deploy the updated
contract, then replace the registry address and pinned fixture commit in Vercel
before promoting the release.

The production alias is <https://equivlab.vercel.app>. Vercel WAF applies a
fixed-window rate limit of 24 requests per 60 seconds per IP to `/api/analyze`;
the Python function also enforces its own bounded per-client limiter.

## 4. Produce live evidence

On the production URL:

1. Confirm **Analyze editor preview instead** is off so the analyzer retrieves the commit-pinned raw URL.
2. Analyze the permissionless tip jar and confirm `FAIL` for `AUTH-01` and `VALUE-01`.
3. Analyze the schema-only validator and confirm `FAIL` for `CONS-01` and `EVID-01`.
4. Analyze the hardened fixture and confirm `MEETS_BASELINE`.
5. Submit the deliberate mismatch and confirm `UNVERIFIABLE` for all twelve rules because source identity was not established.
6. Analyze a commit-pinned ordinary Python file with no `gl.Contract` class and confirm an explicit `UNVERIFIABLE` result rather than `MEETS_BASELINE`.
7. Connect the wallet, request one audit, and wait for a finalized successful receipt before calling the readback authoritative.
8. Reload the page and confirm the existing registry record reproduces the same source URL, source hash, policy, and report. Without the originating receipt, treat this as registry-observed rather than independently finalized.
9. Record the live URL, commit, contract address, deployment transaction, audit transaction, and explorer links in `docs/verification-evidence.md`.
10. For a PROMPT-01 discrepancy, verify that the UI shows both the immutable base report and the separate correction transaction. Its composite report must retain the other eleven rule outcomes and the exact base report/source hashes.

A browser-local report or a submitted preview is not on-chain evidence.
