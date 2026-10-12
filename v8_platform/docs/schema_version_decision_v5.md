# V5 schema version decision

## Decision

The V4 contract was `2.0.0`. V5 freezes the dataset contract as `3.0.0` and the
producer as `platform-v5` (Python distribution `5.0.0`). This is not a software-
version-driven bump: it is required by semantic breaking changes.

## Why this is major

Two existing fields change meaning:

1. `packet_size_bytes` previously claimed encoded-frame size while the producer
   actually used Python representation length. It now has one reproducible
   meaning: canonical serialized application-payload bytes.
2. `sequence_gap_count` previously meant current unresolved history. It now
   implements C's recent-statistics-window semantics and ages old detections
   out.

V5 also requires the resolved attack plan and staged target-side outcome, and
formalizes legitimate versus EXTERNAL participant records. A schema-2 loader
could silently train on the wrong byte/gap meaning, so a minor version would be
unsafe.

## Migration from 2.0.0

- Reject or explicitly branch on schema 2; do not relabel old byte/gap values.
- Read `legitimate_node_count`, `legitimate_node_roles` and
  `external_participants` rather than assuming `len(node_roles)==node_count`.
- Treat `attack_plan` as resolved/executed and retain `requested_attack_plan`
  only for provenance.
- Load the required staged `AttackOutcome` fields.
- Preserve null/availability for unmeasured overhead.
- Continue reading model/defense predictions as outputs, not raw training
  truth.

No automatic migration of old event measurements is supplied because their
true serialized application size and gap timestamps cannot be reconstructed
reliably after export.

## Compatibility rule after freeze

Future optional, meaning-preserving fields may use a 3.x minor release. Any
change to a required field, type, unit, causal scope or the byte/gap/outcome
meaning requires another major review. The machine-readable authority is
`dataset/schema.json`.
