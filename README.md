# EquivLab deterministic analyzer

EquivLab is a deterministic Python source analyzer for the twelve rules in the
`gl-consensus-baseline-1` policy. It combines AST facts with bounded call-path
tracing and has no semantic model dependency.

The four possible report statuses are `MEETS_BASELINE`, `WARN`, `FAIL`, and
`UNVERIFIABLE`. `MEETS_BASELINE` means only that the supplied source revision
meets the implemented rules of the named policy. It is not formal verification
or a security guarantee.

The exact deterministic acceptance conditions and known limits are documented
in [`docs/policy-gl-consensus-baseline-1.md`](docs/policy-gl-consensus-baseline-1.md).
The fixture corpus contains a full `pass.py`/`fail.py` pair for every rule; each
negative fixture isolates one rule in the complete report.

## Live deployment

- Workbench: <https://equivlab.vercel.app>
- Network: GenLayer Bradbury (`testnetBradbury`)
- Registry: `0xB4818B0269DbA2B8F1F567ecB8c25967F2ba8599`
- Pinned fixture commit: `ce007240d1cbb1b7a789348b566cb50cea9b80e7`
- Live matrix: hardened fact checker `MEETS_BASELINE`; permissionless tip jar
  `FAIL` on `AUTH-01` and `VALUE-01`; schema-only validator `FAIL` on `CONS-01`
  and `EVID-01`; deliberate hash mismatch `UNVERIFIABLE` for all twelve rules.

Transaction hashes, the canonical source hash, and authoritative report
readback are recorded in
[`docs/verification-evidence.md`](docs/verification-evidence.md). The live
result applies only to the pinned source revision and implemented policy. It is
not formal verification or a security guarantee.

Phase 3 contract behavior, test layers, and the verified GenVM v0.2.16 direct-mode
boundary are recorded in [`docs/phase3-verification.md`](docs/phase3-verification.md).

## Web workbench and registry boundary

The React + Vite + TypeScript workbench lives in [`web`](web). Its Vercel
Function boundary calls the same deterministic Python analyzer used by the CLI.
Local findings are available without a wallet. The Phase 5 boundary uses
`genlayer-js` for wallet authorization, `request_audit`, receipt reconciliation,
authoritative registry readback, challenges, and superseding revisions. The
production configuration points to the Bradbury registry above; a fresh visitor
can retrieve an existing source-matched audit without connecting a wallet. The UI
does not simulate transactions or on-chain evidence.

Run the local analyzer API and Vite app in separate terminals:

```powershell
python api/analyze.py
cd web
npm ci
npm run dev -- --host 127.0.0.1
```

The workbench opens at `http://127.0.0.1:5173`. It includes the permissionless
tip jar, schema-only validator, hardened fact checker, and hash-mismatch cases.
Reports saved in the archive are browser-local records, not on-chain attestations.
Bundled fixture previews are submitted source bytes and cannot be attested. An
attestation requires a successful server-side retrieval of the exact commit-pinned
GitHub source and a matching canonical SHA-256.

Build and test the web slice:

```powershell
cd web
npm test
npm run build
```

Deploy the `equivlab` directory as the Vercel project root. [`vercel.json`](vercel.json)
builds `web` and packages the Python analyzer with `api/analyze.py`.

The exact GitHub, GenLayer Bradbury, and Vercel release procedure is in
[`docs/deployment-and-submission.md`](docs/deployment-and-submission.md). Keep
the evidence ledger in [`docs/verification-evidence.md`](docs/verification-evidence.md)
honest: deployment fields remain `PENDING` until an explorer or live URL proves
them.

Run the tests:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest
```

Disabling plugin autoload keeps unrelated globally installed pytest plugins
out of this dependency-free test suite.

Run the analyzer without installing it:

```powershell
python analyzer/cli.py fixtures/backdoored_tip_jar/contract.py `
  --url https://raw.githubusercontent.com/<owner>/<repository>/<40-character-commit>/fixtures/backdoored_tip_jar/contract.py `
  --sha256 <canonical-sha256>
```

The source hash is computed after UTF-8 decoding, BOM removal, newline
normalization to LF, and insertion of a final LF when one is absent. The CLI
prints key-sorted JSON; arrays with consensus-relevant rule IDs and findings
are also sorted. `report_sha256` hashes the compact, key-sorted report before
that hash field is added.

## License

[MIT](LICENSE)
