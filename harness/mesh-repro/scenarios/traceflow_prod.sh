# traceflow_prod — the trace ladder on PRODUCTION'S topology and admission (CIRISServer#632).
#
# Same ten rungs as `traceflow`, measured on a node shaped like the QA runner's:
# an agent-typed actor key that compose SPLITS into a node key, an OWNER who
# claims/announces/consents over HTTP, an unblessed key the canonical admits
# Advisory (`NotRootedAtSteward`), and a trust root that arrives as an imported
# genesis bundle rather than a local ceremony (docker-compose.prod.yml).
#
# WHAT IS EXPECTED TODAY. Rungs 1–6 must be green: seal, the carrier row, the
# offer, the owner-authored consent, convergence, and the canonical SERVING the
# agent's bootstrap rounds. Rung 8 `arrive` is RED until CIRISEdge#659 lands —
# edge attributes an inbound frame only from a `Rooted ∧ owns_key` peer, no
# production agent can be Rooted, and the self-attribution hole that hid this
# closed on 2026-09-18 (CIRISServer#607). A red `arrive` here is the mesh's true
# state; a green one is the fix landing. SUCCESS_STAGE is `served` for now and
# moves to `score` with #659 — change it there, not here, and say why.
source "$(dirname "${BASH_SOURCE[0]}")/traceflow.sh"
SCENARIO_NAME="traceflow_prod — production-shaped agent (split, owned, Advisory-admitted, genesis-imported)"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.traceflow.yml -f docker-compose.prod.yml"
SUCCESS_STAGE="served"
SUCCESS_MESSAGE="production-shaped agent reached the canonical: owned, split, Advisory-admitted, bootstrap rounds served. (arrive stays RED until CIRISEdge#659 — read its count above.)"
# seal/trace_att lag the bootstrap rounds by CIRIS_HARNESS_SEAL_DELAY_SECS; requiring them
# keeps the window open so the Attestation rounds RUN inside the measurement and `arrive`
# is read (red, today) rather than skipped by an early SUCCESS at `served`.
REQUIRED_seal=1
REQUIRED_trace_att=1
REQUIRED_consent=1
REQUIRED_converge=1
REQUIRED_served=1
HINT_arrive="EXPECTED RED until CIRISEdge#659: the canonical drops every non-bootstrap frame from an Advisory peer (resolved=(Advisory, owns_key=true), item2=false, door=not_applicable). If this is GREEN, #659 landed — move SUCCESS_STAGE to score."

# ── consent / converge / ship on a SERVER node log the server's own lines ────
# The embedded agent printed harness markers; the composed node logs persist's
# and the reconciler's. Same facts, production's words.
stage_consent()  { harness_log_count agent "emitted directed replication-consent grant"; }
stage_converge() { harness_log_count agent "converged to [1-9][0-9]* consent peers"; }
stage_ship()     { harness_log_count agent '"replication_envelopes_served_total":[1-9]'; }

# ── the production-shape assertions, before any rung is read ────────────────
harness_scenario_prepare() {
  local agent_svc="agent" canon_svc="canonical"
  echo "── traceflow_prod setup: claim + announce + consent + genesis import (the operator's acts, over HTTP) ──"
  # 0. No node dials production. Ever.
  # edge's FFI still LOGS the baked seed and its refused attempts (CIRISEdge#661); only a
  # completed connection means egress happened. The agent REJECTs it with iptables first.
  if [ "$(compose logs 2>/dev/null | grep -c 'connected to 108\.61\.242\.236' || true)" -gt 0 ]; then
    echo "  ✗ a harness node CONNECTED to the PRODUCTION canonical (108.61.242.236) — refusing to measure a run that pollutes production"
    return 1
  fi
  # 1. Wait for the composed node's read-API (the fold binds 4243).
  local waited=0
  until compose exec -T "$agent_svc" python -c 'import urllib.request;urllib.request.urlopen("http://127.0.0.1:4243/health",timeout=3)' >/dev/null 2>&1; do
    sleep 5; waited=$((waited+5)); [ "$waited" -ge 240 ] && { echo "  ✗ agent node never bound 4243 (SERVER-FOLD failed)"; return 1; }
  done
  echo "  ✓ agent node up on 4243 after ${waited}s"
  # 2. The split happened: a NODE key was minted beside the actor key.
  # `grep -q` under pipefail reports a MATCH as failure (SIGPIPE to the writer) — count instead.
  if [ "$(compose logs "$agent_svc" 2>/dev/null | grep -cE 'Minted and registered a separate node key|is an ACTOR' || true)" -eq 0 ]; then
    echo "  ✗ the agent did NOT split (no node key minted) — this is not production's topology; check the actor key registered as \`agent\`"
    return 1
  fi
  echo "  ✓ split: actor key + minted node key"
  # 3. The agent did NOT self-bless (SEED must be absent; the code's own guard must have fired).
  if [ "$(compose logs "$agent_svc" 2>/dev/null | grep -cE 'TEST-ANCHOR ceremony: minted|peer BLESSED' || true)" -gt 0 ]; then
    echo "  ✗ the agent self-blessed under the test root — the SEED leaked through the compose merge; this run would test the wrong topology"
    return 1
  fi
  echo "  ✓ agent unblessed (no ceremony ran)"
  # 4. Claim: mint the owner on the node's console, claim over loopback, keep the session.
  local console="/opt/harness/ciris-server-bin" alias="qa-owner" pin="" code=""
  waited=0
  while [ "$waited" -lt 120 ]; do
    pin="$(compose exec -T "$agent_svc" sh -c 'cat /var/lib/ciris/claim_pin 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
    [ -n "$pin" ] && break; sleep 5; waited=$((waited+5))
  done
  [ -z "$pin" ] && { echo "  ✗ no claim PIN after ${waited}s — the node never armed first-run setup"; return 1; }
  code="$(compose exec -T "$agent_svc" python -c 'import json,urllib.request;print(json.load(urllib.request.urlopen("http://127.0.0.1:4243/v1/federation/node-code",timeout=10))["code"])' 2>/dev/null | tr -d '\r\n')"
  [ -z "$code" ] && { echo "  ✗ /v1/federation/node-code served nothing"; return 1; }
  compose exec -T "$agent_svc" "$console" identity create --backend software --home /var/lib/ciris --key-id "$alias" >/tmp/tfp-mint.out 2>&1 || true
  local claim
  claim="$(compose exec -T "$agent_svc" "$console" claim --backend software --home /var/lib/ciris --key-id "$alias" \
             --node-code "$code" --claim-pin "$pin" --cohort-scope self --target-url http://127.0.0.1:4243 2>/tmp/tfp-claim.err)"
  local token owner
  token="$(printf '%s\n' "$claim" | sed -n '/^{/,$p' | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("access_token") or "")
except Exception: print("")')"
  owner="$(printf '%s\n' "$claim" | sed -n '/^{/,$p' | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("identity_key_id") or "")
except Exception: print("")')"
  [ -z "$token" ] && { echo "  ✗ claim yielded no session:"; tail -3 /tmp/tfp-claim.err | sed 's/^/      /'; return 1; }
  echo "  ✓ claimed — owner=$owner"
  # 5. Announce (the owner re-signs the binding at federation scope — the copy a peer may hold).
  compose exec -T "$agent_svc" python - "$token" <<'PY' 2>/dev/null | sed 's/^/  /'
import json, sys, urllib.request
req = urllib.request.Request("http://127.0.0.1:4243/v1/federation/announce", method="POST",
    headers={"Authorization": "Bearer " + sys.argv[1], "Content-Type": "application/json"}, data=b"{}")
try:
    r = urllib.request.urlopen(req, timeout=30); print("✓ announced:", r.read().decode()[:160])
except Exception as e: print("✗ announce failed:", e)
PY
  # 6. Genesis import: the canonical assembles the bundle the production ceremony would; the agent imports it.
  compose exec -T "$agent_svc" python - "$token" <<'PY' 2>/dev/null | sed 's/^/  /'
import json, sys, urllib.request
canon = "http://canonical:4243"
try:
    b = json.load(urllib.request.urlopen(canon + "/v1/federation/test-genesis-bundle", timeout=30))
except Exception as e:
    print("✗ canonical served no genesis bundle:", e); sys.exit(0)
req = urllib.request.Request("http://127.0.0.1:4243/v1/trust-root/import", method="POST",
    headers={"Authorization": "Bearer " + sys.argv[1], "Content-Type": "application/json"},
    data=json.dumps({"bundle": b["bundle"]}).encode())
try:
    r = urllib.request.urlopen(req, timeout=60); print("✓ genesis imported:", r.read().decode()[:220])
except urllib.error.HTTPError as e:
    print("✗ import refused:", e.code, e.read().decode()[:300])
except Exception as e:
    print("✗ import failed:", e)
PY
  # 7. Consent: the OWNER grants replication to the canonical (production's owner-gated act).
  compose exec -T "$agent_svc" python - "$token" <<'PY' 2>/dev/null | sed 's/^/  /'
import json, sys, urllib.request
canon = "http://canonical:4243"
try:
    rec = json.load(urllib.request.urlopen(canon + "/v1/federation/test-blessed-self-record", timeout=30))
except Exception as e:
    print("✗ could not fetch the canonical's record:", e); sys.exit(0)
body = {"peer_key_id": rec["record"]["key_id"], "peer_key_record": rec,
        "attestation_prefixes": ["capacity:", "chat:", "self:delegates_to:", "trace:"]}
req = urllib.request.Request("http://127.0.0.1:4243/v1/federation/peering", method="POST",
    headers={"Authorization": "Bearer " + sys.argv[1], "Content-Type": "application/json"}, data=json.dumps(body).encode())
try:
    r = urllib.request.urlopen(req, timeout=60); print("✓ consent authored by the owner:", r.read().decode()[:200])
except urllib.error.HTTPError as e:
    print("✗ peering refused:", e.code, e.read().decode()[:300])
except Exception as e:
    print("✗ peering failed:", e)
PY
  return 0
}
