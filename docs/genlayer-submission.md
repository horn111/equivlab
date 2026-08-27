# GenLayer Builder Project submission

## Title

EquivLab — consensus safety workbench

## Notes / description

EquivLab checks one commit-pinned GenLayer Intelligent Contract revision against
the versioned `gl-consensus-baseline-1` policy. A deterministic local analyzer
returns inspectable rule findings. The Bradbury registry independently retrieves
the same pinned source through GenLayer consensus, records an append-only report,
and exposes source-matched readback, challenges, and superseding revisions. The
interface distinguishes an existing registry record from a receipt-proven,
finalized authoritative readback.

The live matrix includes a hardened fact checker that `MEETS_BASELINE`, a
permissionless tip jar that fails `AUTH-01` and `VALUE-01`, a schema-only
validator that fails `CONS-01` and `EVID-01`, and a hash mismatch that is
`UNVERIFIABLE`. `MEETS_BASELINE` is not formal verification or a security
guarantee.

## Evidence links

- Required GitHub repository: <https://github.com/horn111/equivlab>
- Live workbench: <https://equivlab.vercel.app>
- Bradbury registry: <https://explorer-bradbury.genlayer.com/address/0xB4818B0269DbA2B8F1F567ecB8c25967F2ba8599>
- Registry deployment transaction: <https://explorer-bradbury.genlayer.com/tx/0x4d0523f6633f52ad3d4e7b2e9d39efc1aa3f80ce931f126c43fd9e49848a5616>
- Live fixture transactions and report hashes: [`verification-evidence.md`](verification-evidence.md)
