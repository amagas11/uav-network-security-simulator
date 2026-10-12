# V8 × Person-A Final Integration Polish

Date: 2026-09-14. Scope is intentionally limited to commit-stage rollback
consistency and portable packaging. V8_DEFAULT channel semantics, five attacks,
C/RL/calibration, and Person-A cryptographic algorithms are unchanged.

## Input baseline

The input archive had 271 entries and zero UTF-8 filename flags. Python's
default ZIP decoding therefore produced mojibake paths; opening the legacy
archive with `metadata_encoding="gbk"` restored the source tree. This is a
packaging defect, not a code-test failure.

| Suite before changes | Actual result |
|---|---:|
| Person-A upstream | 34 passed |
| V8 excluding Person-A integration | 355 passed |
| Person-A integration | 41 passed |
| V8 combined | 396 passed |
| compileall | PASS |

## Commit-failure counterexample and closure

Before the patch, node 1 could successfully `put()` target epoch 2 before node
2 raised at commit. B revoked epoch 2 and still reported epoch 1 available, but
A `KeyProvider.encrypt()` selected its unchanged `current_epoch=2`; consequently
new traffic failed with `key_unavailable`.

The transaction now records each endpoint's actual valid previous epoch before
SKG starts. On commit failure, the adapter invokes A's public
`rollback_epoch()` for both endpoints. The API marks the failed epoch revoked
and restores the recorded previous epoch only if it remains available. It does
not infer `target-1`, expose key bytes, read private records, or resurrect an
expired/revoked predecessor.

| Test | Behavioral assertion | Result |
|---|---|---:|
| A32 | node1 commit succeeds, node2 raises; epoch1 restored; two new opposite-direction V8 messages transmit at epoch1 and arrive | PASS |
| A33 | handshake transaction, B coordinator/runtime node, and actual A provider encrypt all agree on epoch1; epoch2 not active | PASS |
| A34 | invalid previous key is not restored; encryption remains unavailable and runtime does not crash | PASS |
| A35 | normal network SKG rekey 1→2 still succeeds; new epoch2 and allowed historical epoch1 frames decrypt | PASS |

Only upstream `crypto/key_provider.py` changed. Its SHA-256 changed from
`F44397F02C46A64CA02A6D14E3F88F441E2249F2C930D12D763D7C2A137A21D7`
to `0E9FE467E150900129F4F0E263D592709EF7E5B6C025D41AA14B95E613404D17`.
The hashes of `aead.py`, `skg.py`, `identity.py`, and `credentials.py` are
unchanged. A-CHANGE-002 therefore requires Person-A acceptance as a lifecycle
API addition, while A-CHANGE-001 remains open and untouched.

## Portable package contract

```text
V8_PERSON_A_FINAL/
├── README_INTEGRATION.md
├── v8_platform/
└── person_a_crypto/
    └── upstream/
```

All directory components are ASCII and the integration fixture resolves only
`person_a_crypto/upstream` (or an explicit `PERSON_A_CRYPTO_ROOT`). Seven Chinese
documentation filenames are mapped to explicit ASCII names; their bytes remain
unchanged and `PORTABLE_PATH_MAP.json` records the mapping. The archive builder
filters caches/bytecode/work artifacts and keeps exactly one A upstream source.
Acceptance creates a fresh archive, calls default
`ZipFile.extractall()` without GBK overrides, and imports both A and B adapters
from the extraction.

## Final verified state

```text
V8 PLATFORM: FROZEN
PERSON-A ORIGINAL LIBRARY: PASS
AEAD INTEGRATION: READY
SKG NETWORK INTEGRATION: READY
SKG TWO-PHASE COMMIT: READY
SKG COMMIT-FAILURE ROLLBACK: READY
REKEY INTEGRATION: READY
IDENTITY: READY
CREDENTIAL: READY
FIVE-ATTACK REGRESSION: PASS
C DATA SECURITY: PASS
PACKAGE PORTABILITY: PASS
A-CHANGE-001 REAL-RF RECONCILIATION: OPEN_EXTERNAL_A
A-CHANGE-002 ROLLBACK API: REQUIRES_A_ACCEPTANCE
A CRYPTO INTEGRATION BASELINE: READY
FORMAL A ASSET MATURITY: INTEGRATED_DEVELOPMENT
FINAL FORMAL EXPERIMENT: BLOCKED_EXTERNAL
```
