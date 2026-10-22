#!/usr/bin/env bash
# Does an owner minted on ciris-server 0.5.188 survive the upgrade? (CIRISServer#811, case 2)
#
# A <=0.5.188 app minted the owner's federation ID through the node's own
# POST /v1/self/identity (identity/user: the active_user_alias pointer, the
# `<alias>.backend` marker and the software seed) and self-claimed through
# claim-remote. This replays that on the real 0.5.188 release binary, then boots
# the CURRENT binary on the same home and checks three things: the home is still
# owned (setup/status owner_binding = owned), the owner's password session still
# opens, and the 0.5.188-minted pen resolves (rebind-remote pointed at the node
# itself resolves the pen first, then answers owner_rebind.no_split).
#
# It does NOT reproduce the agent-key split (a 2.9.39 agent's embedded node);
# that needs an agent app home. Software custody only — a Keychain/TPM-sealed
# seed depends on the platform keystore.
#
# Runs in an ubuntu:24.04 container: 0.5.188's ports are baked (4242/4243), so a
# private network namespace keeps it off any node already on this host.
#
#   harness/upgrade/from_0_5_188.sh [path/to/current/ciris-server]
set -euo pipefail

NEW=${1:-target/debug/ciris-server}
[ -x "$NEW" ] || { echo "no current binary at $NEW (cargo build first)"; exit 2; }
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ciris-upgrade-188.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

gh release download v0.5.188 -R CIRISAI/CIRISServer \
    -p 'ciris-server-v0.5.188-x86_64-unknown-linux-gnu.tar.gz' -D "$WORK"
mkdir -p "$WORK/old" && tar -xzf "$WORK"/ciris-server-v0.5.188-*.tar.gz -C "$WORK/old"
chmod +x "$WORK/old/ciris-server"
cp "$NEW" "$WORK/new-ciris-server"

cat > "$WORK/run.sh" <<'EOF'
#!/bin/bash
set -u
W=$1; H=$W/home; A=http://127.0.0.1:4243; PW=correct-horse-battery
fail() { echo "FAIL: $*"; exit 1; }
up() { for _ in $(seq 1 90); do curl -sf $A/health >/dev/null && return 0; sleep 1; done; return 1; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

mkdir -p "$H"
"$W/old/ciris-server" --home "$H" > "$W/old.log" 2>&1 & P=$!
up || { tail -20 "$W/old.log"; fail "0.5.188 never came up"; }
curl -sf -X POST $A/v1/self/identity -H 'content-type: application/json' \
    -d '{"backend":"software","label":"Upgrade Owner"}' >/dev/null || fail "0.5.188 mint"
NC=$(curl -s $A/v1/federation/node-code | python3 -c 'import re,sys; print(re.search(r"CIRIS-V1-[A-Z0-9-]+", sys.stdin.read()).group(0))')
curl -sf -X POST $A/v1/setup/claim-remote -H 'content-type: application/json' \
    -d "{\"node_code\":\"$NC\",\"claim_pin\":\"$(cat "$H/claim_pin")\",\"cohort_scope\":\"self\",\"owner_username\":\"owner\",\"owner_password\":\"$PW\"}" \
    >/dev/null || fail "0.5.188 self-claim"
kill $P; wait $P 2>/dev/null
echo "0.5.188: minted + self-claimed"

"$W/new-ciris-server" --home "$H" > "$W/new.log" 2>&1 & P=$!
up || { tail -30 "$W/new.log"; fail "current never came up on the 0.5.188 home"; }
STATE=$(curl -s $A/v1/setup/status | json 'd["data"]["owner_binding"]["state"]')
[ "$STATE" = owned ] || fail "owner_binding = $STATE"
TOK=$(curl -s -X POST $A/v1/auth/login -H 'content-type: application/json' \
    -d "{\"username\":\"owner\",\"password\":\"$PW\"}" | json 'd.get("access_token") or ""')
[ -n "$TOK" ] || fail "owner password session"
RID=$(curl -s -X POST $A/v1/setup/rebind-remote -H "authorization: Bearer $TOK" \
    -H 'content-type: application/json' -d "{\"target_url\":\"$A\",\"cohort_scope\":\"self\"}" \
    | json 'd.get("reason_id")')
[ "$RID" = owner_rebind.no_split ] || fail "the 0.5.188 pen did not resolve (reason_id=$RID)"
kill $P; wait $P 2>/dev/null
echo "PASS: owned after upgrade; owner session opens; the 0.5.188-minted pen resolves"
EOF
chmod +x "$WORK/run.sh"

# The container runs as root (apt); hand the home back so the trap can remove it.
docker run --rm -v "$WORK:$WORK" ubuntu:24.04 bash -c \
    "apt-get update -qq >/dev/null && apt-get install -y -qq curl python3 >/dev/null 2>&1; \
     $WORK/run.sh $WORK; rc=\$?; chown -R $(id -u):$(id -g) $WORK; exit \$rc"
