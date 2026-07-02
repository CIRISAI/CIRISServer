# CIRISServer opaque wire-vocabulary kinds (CC 0.7 Tier-2)

**Steward:** CIRISAI/CIRISServer.
**Range:** `0x0000_0000..=0x0000_FFFF` (per CIRISRegistry
`manifests/WIRE_VOCABULARY.md` v1.0.1 §3.1 — every ratifying repo stewards its
own `kind` range and publishes `kind → semantics`; edge carries the payload as
opaque bytes, "reach, not meaning").
**Cohabitation gate:** `tests/wire_vocabulary_gate.rs` pins the ratified
vocabulary hash `c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c`
against `ciris_edge::WIRE_VOCABULARY_HASH`, so a drifting edge bump fails this
repo's build.

Adding a row here is a reviewed code change; a kind is never reused after
retirement.

## Allocations

| kind | envelope | semantics | inner schema (app-owned) | auth |
|---|---|---|---|---|
| `0x0000_0001` | `OpaqueRequest` / `OpaqueResponse` (Ephemeral) | **Mesh control-plane relay** (CIRISServer#128 Phase D, `FSD/RNS_CONTROL_RELAY.md` + `FSD/EDGE_8_0_OPAQUE_MIGRATION.md` §6): an owner administers an owned node by federation `key_id` over RNS — the allow-listed owner-op set (`src/mesh_relay.rs::RELAYABLE`; wipe/claim/mint/login are never relayable). | `ControlPayload { headers, envelope_b64 }` where `headers` is the fabric `x-ciris-*` signature-header trio and `envelope_b64` is base64 of the EXACT signed JSON bytes of `ControlEnvelope { v, target_key_id, method, path, body, nonce, ts }` (`src/mesh_relay.rs`). Canonicalization = **exact-bytes-signed**: the serialized envelope bytes are signed, transmitted, and verified verbatim — no re-serialization on either side. The response payload is the dispatched v1 handler's body bytes; `OpaqueResponse.status` is its HTTP status. | Inner **owner fed-ID hybrid signature** (Ed25519 + ML-DSA-65, `HybridPolicy::Strict`) verified against the TARGET node's federation directory (`verify::verify_request`), and the verified signer must act for the target's own owner-binding (`is_steward_bound` + `signer_acts_for`). The OUTER edge envelope carries the transport (node-signer) identity only — it is never the authorization principal. Replay: `nonce` + `ts` (±300 s) per signer. |
| `0x0000_0002+` | — | *reserved* for future control ops (e.g. a mesh health probe). | — | — |
