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

Install and authenticate the current GenLayer CLI, select Bradbury, and deploy
the single source contract:

```powershell
genlayer network testnet-bradbury
genlayer deploy --contract contracts/consensus_safety_registry.py
```

Save the deployment transaction hash and the returned contract address. Confirm
the transaction in the Bradbury explorer before configuring the frontend. The
official CLI workflow and current network setup are documented by GenLayer:

- <https://docs.genlayer.com/developers/intelligent-contracts/deploying/cli-deployment>
- <https://docs.genlayer.com/developers/intelligent-contracts/deploying/network-configuration>

## 3. Configure and deploy Vercel

Use the repository's `equivlab` directory as the Vercel project root. The checked-in
`vercel.json` builds `web/dist` and exposes the Python analyzer at `/api/analyze`.

Set these production environment variables:

```text
VITE_NETWORK_NAME=testnetBradbury
VITE_REGISTRY_ADDRESS=<deployed-0x-address>
VITE_GENLAYER_RPC_URL=https://rpc-bradbury.genlayer.com
VITE_EXPLORER_BASE_URL=https://explorer-bradbury.genlayer.com
VITE_DEMO_REPOSITORY=<owner>/<repository>
VITE_DEMO_COMMIT=<full-40-character-commit>
```

The RPC and explorer values may be omitted to use the values shipped by the
installed `genlayer-js` chain definition. Keeping them explicit makes the release
configuration reviewable.

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

A browser-local report or a submitted preview is not on-chain evidence.
