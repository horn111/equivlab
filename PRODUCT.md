# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React + Vite + TypeScript. Vercel is the deployment target. The user selected a code-first workflow and may request a comp-first redesign after reviewing the implementation.

## Users

Primary users are GenLayer builders preparing a Builder Project submission or moving an Intelligent Contract toward a live network. Reviewers and integrating protocols are secondary users who need to understand what was checked and whether GenLayer consensus is load-bearing.

## Product Purpose

EquivLab is a consensus-safety workbench and on-chain attestation gate. It checks one commit-pinned Python Intelligent Contract revision against one named, versioned policy, gives immediate deterministic local findings, and presents the authoritative on-chain result and immutable history.

Success means a reviewer can understand the backdoored tip jar, schema-only fact checker, hardened revision, and an unverifiable request without reading the repository.

## Positioning

EquivLab checks whether consensus-critical boundaries meet an inspectable policy. It starts after structural validity and source authenticity. It does not generate or deploy contracts, benchmark validators, perform formal verification, or declare a protocol secure.

## Operating Context

The primary workflow uses a public GitHub repository, exact commit, Python contract path, canonical source hash, local AST findings, wallet-backed audit submission, transaction reconciliation, authoritative contract readback, challenges, and superseding revisions.

The UI must distinguish local deterministic analysis from the on-chain validator result at every stage.

## Capabilities and Constraints

- Policy v1 is `gl-consensus-baseline-1` with twelve deterministic rule cores.
- Result states are `MEETS_BASELINE`, `WARN`, `FAIL`, and `UNVERIFIABLE`.
- `MEETS_BASELINE` is a baseline result, not formal verification or a security guarantee.
- Source input must resolve to a commit-pinned raw GitHub HTTPS URL and canonical SHA-256.
- Audit history is immutable. A fixed revision supersedes an earlier audit without erasing it.
- The web workbench provides local preflight, real transaction lifecycle, retry and reconciliation, authoritative readback, revision comparison, and shareable local reports.
- Network and registry address are deployment configuration. Production uses Bradbury registry `0xB4818B0269DbA2B8F1F567ecB8c25967F2ba8599`; missing or invalid configuration must remain explicit rather than fabricated.

## Brand Commitments

The product name is EquivLab. Language must be precise, technical, adversarial, and restrained. Avoid generic security claims and avoid describing results as certification, proof, formal verification, or guaranteed safety.

## Evidence on Hand

- Versioned policy: `policies/gl-consensus-baseline-1.json`
- Production contract: `contracts/consensus_safety_registry.py`
- Reference fixtures: `fixtures/backdoored_tip_jar`, `fixtures/schema_only_fact_checker`, and `fixtures/hardened_fact_checker`
- Analyzer and contract test suites: `tests/analyzer`, `tests/contract`, and `tests/direct`
- Verified release result: 117 dependency-free Python tests and 7 GenVM v0.2.16 direct-mode tests passed
- Phase 5 frontend integration: `genlayer-js` wallet authorization, registry writes, receipt reconciliation, authoritative readback, challenge, and supersession flows
- Production URL: `https://equivlab.vercel.app`
- Bradbury live matrix: audit `0` `MEETS_BASELINE`; audits `1` and `2` `FAIL`; audit `3` `UNVERIFIABLE`
- No customer logo, testimonial, certification, or usage metric exists. Future surfaces must not invent them.

## Product Principles

1. Bind every claim to an exact source revision and policy.
2. Show local evidence quickly, but treat on-chain readback as authoritative.
3. Fail visibly and recoverably when evidence cannot be reproduced.
4. Preserve challenged and superseded history instead of rewriting it.
5. Prefer categorical findings and inspectable rule IDs over synthetic security scores.

## Accessibility & Inclusion

The web interface must be keyboard operable, preserve visible focus, expose status without color alone, support reduced motion, and remain usable at mobile and desktop widths.
