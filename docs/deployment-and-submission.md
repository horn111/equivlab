# Deployment and submission runbook

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

Verify that all three raw URLs return the committed files:

```text
https://raw.githubusercontent.com/<owner>/<repository>/<commit>/fixtures/backdoored_tip_jar/contract.py
https://raw.githubusercontent.com/<owner>/<repository>/<commit>/fixtures/schema_only_fact_checker/contract.py
https://raw.githubusercontent.com/<owner>/<repository>/<commit>/fixtures/hardened_fact_checker/contract.py
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

## 4. Produce live evidence

On the production URL:

1. Disable **Use bundled preview** so the analyzer retrieves the commit-pinned raw URL.
2. Analyze the permissionless tip jar and confirm `FAIL` for `AUTH-01` and `VALUE-01`.
3. Analyze the schema-only validator and confirm `FAIL` for `CONS-01` and `EVID-01`.
4. Analyze the hardened fixture and confirm `MEETS_BASELINE`.
5. Connect the wallet, request one audit, and wait for an accepted or finalized successful receipt.
6. Reload the page and confirm authoritative readback reproduces the same source URL, source hash, policy, and report.
7. Record the live URL, commit, contract address, deployment transaction, audit transaction, and explorer links in `docs/verification-evidence.md`.

A browser-local report or a submitted preview is not on-chain evidence.

## 5. GenLayer Builder Project submission

Use the GitHub repository as required evidence. Add the live Vercel URL and the
Bradbury explorer links as separate evidence items if the form allows them.
The description should state what the implemented contract does, where GenLayer
consensus is essential, and the calibrated result boundary:

> EquivLab checks one commit-pinned GenLayer Intelligent Contract revision against
> the versioned `gl-consensus-baseline-1` policy. Deterministic local analysis gives
> immediate findings; an Intelligent Contract independently retrieves and evaluates
> the same revision through GenLayer consensus, stores an immutable report, and
> exposes authoritative readback, challenge, and supersession history. `MEETS_BASELINE`
> is not formal verification or a security guarantee.

Do not submit until the evidence ledger has no `PENDING` entries in the required
deployment rows.
