# Cross-implementation parity harness (CIRISLensCore#11)

The signature-critical guarantee for the fold-into-agent: a trace
lens-core seals must verify under every federation verifier's recomputed
canonical bytes. That holds iff lens-core's `capture::seal::canonical_bytes`
is **byte-identical** to CIRISAgent's `Ed25519TraceSigner._build_canonical_message`.
This harness pins that equality against the agent's *real* output — not a
hand-written expected string.

## Files

- **`generate_canonical_fixtures.py`** — dev-time generator. Imports the
  agent's real `_build_canonical_message` from a CIRISAgent checkout,
  builds a battery of diverse `CompleteTrace` fixtures (floats,
  `ensure_ascii` unicode, 0/false retention, empty-field stripping,
  `deployment_profile`, the full event taxonomy, agent_id_hash
  denormalization), and captures the exact signed bytes.
- **`canonical_fixtures.json`** — the committed output: `{name, trace,
  expected_canonical}` per fixture. The agent's signed bytes are the
  source of truth.

## Consumer

The hermetic Rust test
`capture::seal::tests::canonical_bytes_match_agent_fixtures`
`include_str!`s the committed JSON, reconstructs each `CompleteTrace`,
computes `canonical_bytes`, and asserts byte-identity. **CI runs it with
no agent checkout** — the committed JSON is self-contained.

## Regenerating

When the agent's §8 canonical format moves (a `TRACE_SCHEMA_VERSION`
bump, a new signed field, a taxonomy change), regenerate:

```sh
python3 tests/parity/generate_canonical_fixtures.py \
    --agent ~/CIRISAgent \
    --out tests/parity/canonical_fixtures.json
```

A diff in `canonical_fixtures.json` **is** the wire-format change
surfacing. Review it as you would a wire-format change: if lens-core's
`build_canonical_envelope` doesn't move in lockstep, the Rust test goes
red — exactly the early-warning the harness exists to give.
