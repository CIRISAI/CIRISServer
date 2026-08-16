#!/usr/bin/env bash
# Run a command with CIRIS_TEST_DSN pointed at a Postgres, and REFUSE rather
# than silently fall back to SQLite.
#
# WHY THIS EXISTS
#
# `tests/genesis_bundle_validate.rs` defaults to `sqlite::memory:` when
# CIRIS_TEST_DSN is unset — which is the right default for a fixture and the
# wrong one for a check whose entire purpose is to ask the OTHER backend.
# CIRISServer#381 shipped because the genesis validation only ever ran on
# SQLite: SQLite has no `uuid` type, so it stored the baked bundle's symbolic
# attestation ids fine while every Postgres node aborted stage 1 at character 0.
# Two production agents crash-looped 151 and 223 times against a green suite.
#
# So a run that cannot reach a Postgres must FAIL, not skip. A skipped check
# that prints `ok` is the precise failure mode this repo keeps paying for: "did
# not check" and "checked, fine" must never be the same result.
#
#   scripts/with_test_postgres.sh cargo test --test genesis_bundle_validate -- --test-threads=1
#
# Bring your own:      CIRIS_TEST_DSN=postgres://... scripts/with_test_postgres.sh <cmd>
# Otherwise it starts a throwaway container and removes it on the way out.
set -euo pipefail

if [ $# -eq 0 ]; then
  echo "usage: $0 <command...>" >&2
  exit 2
fi

# Caller supplied one — use it untouched and do not manage any container.
if [ -n "${CIRIS_TEST_DSN:-}" ]; then
  echo "with_test_postgres: using caller's CIRIS_TEST_DSN"
  exec "$@"
fi

if ! command -v docker >/dev/null 2>&1; then
  cat >&2 <<'EOF'
with_test_postgres: no CIRIS_TEST_DSN and no docker — REFUSING to run.

This check exists to exercise the Postgres path. Running it without one would
pass on SQLite and report `ok` for a backend it never touched, which is exactly
how CIRISServer#381 reached production.

Give it a database:

  CIRIS_TEST_DSN=postgres://user:pass@host:5432/db scripts/with_test_postgres.sh <cmd>

or install docker and re-run.
EOF
  exit 1
fi

NAME="ciris-preflight-pg-$$"
PORT="${CIRIS_TEST_PG_PORT:-55433}"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" \
  -e POSTGRES_PASSWORD=ciris -e POSTGRES_DB=ciris \
  -p "${PORT}:5432" postgres:16-alpine >/dev/null

# `docker run -d` returns as soon as the container is created; the server is not
# accepting connections yet, and a connect against a half-started Postgres fails
# in a way that reads exactly like a genuine refusal.
for _ in $(seq 1 45); do
  if docker exec "$NAME" pg_isready -U postgres >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [ "${ready:-0}" != "1" ]; then
  echo "with_test_postgres: container never became ready — failing rather than falling back" >&2
  docker logs "$NAME" 2>&1 | tail -20 >&2
  exit 1
fi

export CIRIS_TEST_DSN="postgres://postgres:ciris@127.0.0.1:${PORT}/ciris"
echo "with_test_postgres: ${CIRIS_TEST_DSN}"
"$@"
