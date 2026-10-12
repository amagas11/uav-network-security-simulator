# V8 × Person-A Crypto 集成测试报告

日期：2026-09-14。final polish 输入 ZIP 先以 GBK metadata compatibility 恢复；修改前
baseline 确认后才处理 commit rollback 与 portable packaging。A upstream 只有一份，未复制
到 `swarm_sim`；仅 `key_provider.py` 增加 lifecycle rollback API，密码算法未修改。

## 独立 baseline

| Suite | Command | Actual result |
|---|---|---:|
| Input compile baseline | `python -m compileall -q ...` | PASS |
| Input V8 original baseline | `python -m pytest -q --ignore=tests/integration/person_a` | 355 passed, 2 dependency warnings |
| Input A original baseline | `python -m pytest -q` in upstream | 34 passed |
| Input A/B integration baseline | `python -m pytest -q tests/integration/person_a` | 41 passed |
| Input combined baseline | `python -m pytest -q` | 396 passed, 2 dependency warnings |
| Patched A provider suite | `python -m pytest -q` in upstream | 37 passed |
| Final V8 original | `python -m pytest -q --ignore=tests/integration/person_a` | 355 passed, 2 dependency warnings |
| Final A/B integration | `python -m pytest -q tests/integration/person_a` | 46 passed |
| Final combined complete | `python -m pytest -q` | 401 passed, 2 dependency warnings |
| 22-scenario mechanism matrix | `python -m pytest -q tests/acceptance/test_final_scenario_mechanism_matrix_v6.py` | 23 passed |
| C data/formal gates | three C acceptance modules | 26 passed |
| V2–V7 regressions + parity | regression directory + parity selections | 92 passed, 2 dependency warnings |
| deterministic/reproducibility selection | `python -m pytest -q -k "deterministic or reproducib"` | 3 passed |

Warnings come from FastAPI/Starlette TestClient deprecations (`httpx2` and AnyIO alias), not
from integration failures.

## A source integrity

Only `key_provider.py` changed. Before/after SHA-256 evidence:

| Upstream file | SHA-256 |
|---|---|
| `crypto/aead.py` | `E00329009EF4D15C55B4EE9EF08123A3FBAEF764B6C089AEF744D5BDD0EC2124` |
| `crypto/key_provider.py` | before `F44397F02C46A64CA02A6D14E3F88F441E2249F2C930D12D763D7C2A137A21D7`; after `0E9FE467E150900129F4F0E263D592709EF7E5B6C025D41AA14B95E613404D17` |
| `crypto/skg.py` | `393722CA6EE2A145F63150C36DA1F42A4625BBDD9398B20B92D497E557E76441` |
| `crypto/identity.py` | `166A1473ED74294C12878042F2D5F47907F48A467566606E73BB8C223CADDE79` |
| `crypto/credentials.py` | `E826D0609F0FBC7B2DE0ED29D3A9D3B1C6588AD09CEA216FCC6C3C85A1061D9B` |

The modification adds only `rollback_epoch()` and its event constant. It neither returns nor reads
raw key material outside A. `crypto/test_vectors.json` is not imported by runtime. This extension is
tracked as A-CHANGE-002 and requires Person-A acceptance into a formal upstream release.

## Integration acceptance evidence

| ID | Behavior evidence | Result |
|---|---|---|
| A03 | Production `KeyProvider`, PersonA coordinator and crypto adapter have no `_key_material`; only explicit `TestKeyMaterialProvider` retains it | PASS |
| A04 | V8 queue→Frame→PHY→receiver roundtrip delivers original payload; AUTH_RESULT includes PASS, key ID and AES-256-GCM | PASS |
| A05–A06 | Ciphertext tamper, wrong receiver, reversed direction and wrong key return failure with `payload=None` | PASS |
| A07 | Missing key produces no STATUS TX, no plaintext, recoverable AUTH_RESULT and `skg_required=true` | PASS |
| A08–A10 | V8 Probe feeds two endpoint-local A observations; one business session; 4 signed control messages (two RECONCILE, two CONFIRM) traverse TX/RX; pairwise two-phase commit 后双方 AVAILABLE；next business packet decrypts | PASS |
| A11–A12 | Non-neighbor or missing/disabled direct link yields SKG failure and no key at either endpoint | PASS |
| A13 | Modified Ed25519 signature prevents confirmation/key commit | PASS |
| A14 | defense rekey returns UPDATING without early epoch change; network SKG completes epoch 2; new encrypt uses epoch 2; allowed old frame decrypts during transition | PASS |
| A15 | FDI gradual values are 105/110/115 before A encryption; AEAD PASS at receiver; out-of-range decrypted content still reaches deterministic FDI detector | PASS |
| A16 | Post-encryption ciphertext tamper produces AUTH FAIL and no business-state execution | PASS |
| A17–A18 | non-sensitive plaintext is ordinary control, AES-GCM sensitive traffic is ciphertext-only, explicit unprotected sensitive control remains exposure-positive | PASS |
| A19 | immediate/delayed replays preserve AEAD material but B returns DUPLICATE; old-session rotation returns WRONG_SESSION | PASS |
| A20 | EXTERNAL no-key spoof claiming GCS cannot authenticate and does not isolate legitimate GCS | PASS |
| A21–A22 | Flooding load remains real; generic broken/interfered SKG link times out and never fabricates a key (JAMMING is no longer a current AttackPlan subtype) | PASS |
| A23 | simulated fingerprint authorizes legitimate startup/join/sensitive command; changed/copied profile fails credential verification | PASS |
| A24 | Person-A secret scan, DatasetValidator and platform leakage audit pass exported dataset/runtime/API surfaces | PASS |
| A25–A27 | factories create independent nonce/key/SKG/credential state; Manager and API-controller reset are fresh; Direct/Manager/FastAPI/Batch/RL all use Person-A bundle provenance | PASS |
| A28 | 丢失一侧 CONFIRM 后先观察到 exactly one pending confirm；两端 target epoch 都非 AVAILABLE；timeout 后 FAILED，旧 epoch ciphertext decrypt PASS | PASS |
| A29 | 正反方向重复请求同一 pair/session/target epoch；只有一个 handshake/probe，第二次返回 `existing_rekey_in_progress` | PASS |
| A30 | 有效 Ed25519 签名但 cross-confirm blob 冲突；提交前 FAILED，双方无 key | PASS |
| A31 | `V8_DEFAULT` 固定样本逐值等于原始 V8；compat 只能显式选择，metadata 为 `PERSON_A_V01_COMPAT_TEST` 且 formal readiness 被阻塞 | PASS |
| A32 | node1 epoch2 commit 后 node2 抛异常；双方恢复 effective epoch1，随后 A→B 与 B→A 两条全新业务均 TX epoch1、decrypt PASS | PASS |
| A33 | handshake transaction、B coordinator/runtime node、A provider actual encrypt 三层均观察 epoch1；target epoch2 为 revoked/unavailable | PASS |
| A34 | rekey 前 previous epoch 已 invalid 时不复活；两端 encrypt 返回 key_unavailable，runtime 继续 | PASS |
| A35 | 正常 epoch1→epoch2 SKG/rekey 仍 AVAILABLE；新 frame epoch2 PASS，允许的历史 epoch1 frame 仍 PASS | PASS |
| Package | canonical `V8_PERSON_A_FINAL/{v8_platform,person_a_crypto/upstream}`；cache-free；default `extractall()` + fresh imports/tests | PASS |
| Formal asset boundary | injected identity-store and credential-service factories receive each fresh run config; non-secret provider version records their mode | PASS |

## Run provenance example

```json
{
  "key_provider": {
    "name": "PersonAKeyCoordinator",
    "version": "person-a-0.1+v8-adapter-1.2+skg-v8-network-2pc+rollback+identity-ed25519-test-only-generated-identity",
    "status": "PERSON_A_INTEGRATED_DEVELOPMENT"
  },
  "crypto_provider": {
    "name": "PersonACryptoProvider",
    "version": "person-a-0.1+v8-adapter-1.0+AES-256-GCM",
    "status": "PERSON_A_INTEGRATED_DEVELOPMENT"
  },
  "security_provider_maturity": "TEST",
  "probe_profile": "PERSON_A_V01_COMPAT_TEST",
  "experiment_readiness": "BLOCKED_EXTERNAL"
}
```

No raw key, private PEM, credential master/serial, quantized secret or SKG candidate key is
present in this record.

## Result classification

```text
PERSON-A CRYPTO LIBRARY: PASS
A→B ADAPTER: READY
A AEAD IN V8: READY
A SKG USING V8 PROBE: READY
A SKG OVER V8 NETWORK: READY
A IDENTITY HANDSHAKE: READY
A TERMINAL CREDENTIAL INTEGRATION: READY
A REKEY INTEGRATION: READY
SKG COMMIT-FAILURE ROLLBACK: READY
V8 FIVE-ATTACK REGRESSION WITH A: PASS
C DATA SECURITY AFTER A INTEGRATION: PASS
B PLATFORM REGRESSION: PASS
PACKAGE PORTABILITY: PASS
A-CHANGE-001 REAL-RF RECONCILIATION: OPEN_EXTERNAL_A
A-CHANGE-002 ROLLBACK API: REQUIRES_A_ACCEPTANCE
FORMAL A ASSET MATURITY: INTEGRATED_DEVELOPMENT
FINAL FORMAL EXPERIMENT: BLOCKED_EXTERNAL
```

No known P1 B-adapter defect remains in the tested closure scope. Formal identity/credential
assets and validation on approved real reciprocal RF data remain external prerequisites.
In particular, A v0.1 exact-match SKG does not claim compatibility with `V8_DEFAULT` or real
RF; explicit compatibility mode is TEST_ONLY and A-CHANGE-001 records the formal gap.
