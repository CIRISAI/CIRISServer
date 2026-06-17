# QA — Python conformance against the Rust `ciris-server`

This directory proves the Rust engine (`ciris-server`) is a **behaviour-correct
drop-in** for the Python agent on the **fabric surfaces it absorbed**
(auth / identity / consent / erasure / lens read API — CIRISServer#9). It does so
by running the **agent's own, unmodified QA-runner module definitions** against a
**live `ciris-server`** and showing the fabric-relevant expectations pass. It is
conformance/validation — NOT a port of the QA runner to Rust.

See `FSD/QA_AGAINST_RUST.md` for the module classification, per-module results,
and the bottom-line drop-in verdict.

## What was copied here (READ-ONLY source: `~/CIRISAgent`, never edited)

| Path here | Copied from | Why |
|---|---|---|
| `qa_runner/` | `CIRISAgent/tools/qa_runner/` | the agent's QA runner — `config.py` (the `QATestCase`/`QAModule` definitions = the encoded EXPECTED behaviour), `modules/*.py` (~61 modules), `runner.py`, `server.py`, `staged_env.py`, `test_data/`, `requirements.txt`. Verbatim, unmodified. |
| `ciris_sdk/` | `CIRISAgent/ciris_sdk/` | the SDK package the SDK-style modules (`consent_tests`, `dsar_tests`, `partnership_tests`, `qa_test_sdk.py`) import. Verbatim, unmodified. |

`requirements.txt` (kept): `requests`, `rich`, `psutil`, `pydantic` — all already
present in the environment, plus `cryptography` (for the seed step below).

## What is NEW here (the no-auto-start conformance harness)

These are the only non-copied files; they do **not** modify the agent code:

- **`run_fabric.py`** — the conformance driver. It loads the agent's UNMODIFIED
  `qa_runner.config` + `modules/api_tests.py` + `modules/sdk_tests.py` definition
  files directly (bypassing the package `__init__.py` side-effects, which eagerly
  import the agent brain — `ciris_sdk → ciris_engine`), and executes each
  `QATestCase` against a running `ciris-server` using the **exact pass criterion
  the agent's `QARunner._execute_single_test` uses**: `status_code ==
  expected_status` (+ optional `validation_rules`/`custom_validation`), with
  retries, Bearer-token auth seeded from `POST /v1/auth/login` — i.e. the mission's
  `--no-auto-start` + `--url` mode. It also adds direct contract probes for the
  CEG-native fabric routes that have no matching agent `QATestCase`
  (`/v1/auth/consent`, `/v1/auth/erasure`, `/v1/auth/attestation`, `/v1/self/login`,
  `/v1/identity`).
- **`seed_wa_cert.py`** — staged-environment setup. `ciris-server` is headless
  (no setup wizard — that flow lives in the brain), so this writes the QA admin
  user (`jeff`) into the `cirislens_wa_cert` table with a `password_hash` produced
  by the **agent's own KDF** (`cryptography.PBKDF2HMAC(SHA256, len=32,
  salt=token_bytes(32), iter=100000)` → `b64(salt‖key)`). That an agent-produced
  hash authenticates against the Rust `session.rs::verify_password` IS the
  byte-compat proof.
- **`fabric_results.json`** — the captured machine-readable run output.

## How to reproduce

```bash
# 1. build + run ciris-server with a throwaway home (read API on listen+1 = 4243)
cargo build --release -p ciris-server
CIRIS_HOME=$(mktemp -d) CIRIS_SERVER_LISTEN_ADDR=127.0.0.1:4242 \
  ./target/release/ciris-server &

# 2. seed the QA admin user (agent-KDF password hash) into the live DB
python3 qa/seed_wa_cert.py "$CIRIS_HOME/data/ciris_engine.db" jeff qa_test_password_12345 root

# 3. run the agent's QA module definitions against the live node (no-auto-start)
python3 qa/run_fabric.py --url http://127.0.0.1:4243 --json-out qa/fabric_results.json
```

## Why not invoke `QARunner` directly?

`QARunner.__init__` imports `qa_runner.server` (the `APIServerManager` auto-start
machinery) and `_module_metadata`, both of which assume the agent dev-tree and
boot a Python agent + mock LLM. The mission requires pointing at an
**already-running** node and **never** auto-starting. `run_fabric.py` is that
no-auto-start harness — it consumes the agent's module definitions and the
runner's execution contract verbatim, without the brain-coupled boot path.
