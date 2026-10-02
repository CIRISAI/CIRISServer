#!/usr/bin/env bash
# scenarios/manifest.sh — a CI pipeline publishes a build; a second registry node ends up holding it.
#
# THE CLAIM. A build is not a row a registry signs. It is two things a blessed
# pipeline publishes and any node can check: a Contribution (a `scores` row on
# `provenance:build_manifest:{target}:v1`, signed by the pipeline's own key)
# and the manifest bytes (a commons blob the row names by hash). Publish both
# to ONE registry node; the row replicates, the other registry node pulls the
# bytes, and it then serves the build with provenance it re-verified itself.
#
# THE TOPOLOGY (docker-compose.manifest.yml): two nodes blessed for the registry
# slice on a synthetic software trust root, and one unblessed bystander.
#
# WHAT EACH RUNG MEANS
#
#   rooted        all three nodes rooted to the test trust root.
#   conferred     both registry nodes say the registry slice is CONFERRED. The
#                 slice is conferred by the accord, never configured, so this is
#                 the first thing that has to be true and nothing sets it.
#   holds_commons registry B agreed to hold commons blobs, and named registry A
#                 as a holder it will pull from. A node not conferred the slice
#                 declines the commons; without this rung the bytes never move.
#   peered        the registries admitted each other, both ways.
#   owners_accept registry A holds both owners' acceptance of the trust root.
#                 Edge roots a peer through its owner; without this a peer is
#                 Attributed, and third-party rows are withheld from it.
#   refused       NEGATIVE, at the door. A pipeline with a real key, a valid
#                 signature and a matching manifest — and no blessing — is
#                 refused `pipeline_not_blessed`. A valid signature is not
#                 authorization.
#   admitted      the blessed pipeline's Contribution is admitted by registry A.
#                 This one holds a delegation GRANT and no role on its record.
#   ceremony_admitted  a second pipeline, blessed the way the accord's CI-key
#                 ceremony blesses one (infra:attest co-scrubbed onto its key
#                 record, no grant), is admitted with standing `accord_role`.
#   ceremony_on_b registry B serves that build too, bytes included.
#   served_on_a   registry A serves the build, holding the manifest bytes.
#   row_on_b      registry B serves the build: the Contribution replicated and
#                 registry B re-verified it against its OWN directory and its
#                 OWN accepted root.
#   blob_on_b     registry B holds the manifest bytes, and they hash to what the
#                 Contribution attests. This is the anti-entropy rung.
#   unblessed_is_nowhere  NEGATIVE. No node serves the unblessed pipeline's
#                 build. Latched: a build that was served once and then
#                 withdrawn was still served.
#
# `bystander` is reported in the evidence and is not a rung: whether an
# unconferred node should hold a manifest it was offered is a policy this
# scenario observes rather than asserts.

SCENARIO_NAME="manifest"
COMPOSE_FILES="-f docker-compose.chat.yml -f docker-compose.manifest.yml"
PROJECT="${PROJECT:-ciris-manifest}"
SUCCESS_STAGE="blob_on_b"
STAGES=(rooted conferred holds_commons peered owners_accept refused admitted ceremony_admitted served_on_a row_on_b blob_on_b ceremony_on_b unblessed_is_nowhere)
REQUIRED_ceremony_admitted=1
REQUIRED_ceremony_on_b=1

# OPTIONAL: a Contribution minted by another producer, e.g. CIRISVerify's
# `ciris-build-sign sign --emit-contribution`. Point MAN_EXTERNAL_PIPELINE at a
# directory holding contribution.json, manifest.bin, ed25519.pub and
# mldsa65.pub. The test root blesses the PUBLIC keys the ceremony way; the
# harness never signs as that pipeline. Two rungs join the ladder when set.
MAN_EXTERNAL_PIPELINE="${MAN_EXTERNAL_PIPELINE:-}"
if [ -n "$MAN_EXTERNAL_PIPELINE" ]; then
  STAGES+=(external_admitted external_on_b)
  REQUIRED_external_admitted=1
  REQUIRED_external_on_b=1
fi
REQUIRED_refused=1
REQUIRED_row_on_b=1
REQUIRED_blob_on_b=1
REQUIRED_unblessed_is_nowhere=1

MAN_STATE="${TMPDIR:-/tmp}/ciris-manifest-${PROJECT}"
MAN_A="canonical"
MAN_B="node-a"
MAN_BYSTANDER="node-b"
MAN_NODES="$MAN_A $MAN_B $MAN_BYSTANDER"
MAN_CONSOLE="/opt/harness/ciris-server-bin"
MAN_VERSION="${MAN_VERSION:-9.9.9}"

_man_load() {
  # shellcheck source=/dev/null
  [ -f "$MAN_STATE/vars.sh" ] && . "$MAN_STATE/vars.sh"
  return 0
}

# Ask a node's HTTP API. The body travels on STDIN-free argv as a FILE inside
# the container, because a Contribution is ~16 KiB of base64 and an argv that
# long is a quoting accident waiting for its day.
_man_api() {
  local svc="$1" method="$2" path="$3" bodyfile="${4:-}" token
  _man_load
  eval "token=\${MAN_TOKEN_${svc//-/_}:-}"
  if [ -n "$bodyfile" ]; then
    compose cp "$bodyfile" "$svc:/tmp/man-body.json" >/dev/null 2>&1 || true
  fi
  compose exec -T "$svc" python - "$token" "$method" "$path" "${bodyfile:+/tmp/man-body.json}" <<'PY' 2>/dev/null
import json, sys, urllib.request, urllib.error
token, method, path, bodyfile = sys.argv[1:5]
data = open(bodyfile, "rb").read() if bodyfile else None
headers = {"Content-Type": "application/json"}
if token:
    headers["Authorization"] = "Bearer " + token
req = urllib.request.Request("http://127.0.0.1:4243" + path, method=method, data=data, headers=headers)
def parse(raw):
    try: return json.loads(raw.decode() or "{}")
    except Exception: return {"raw_len": len(raw)}
try:
    r = urllib.request.urlopen(req, timeout=45)
    print(json.dumps({"status": r.status, "body": parse(r.read())}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "body": parse(e.read())}))
except Exception as e:  # noqa: BLE001
    print(json.dumps({"status": 0, "body": {"detail": repr(e)[:200]}}))
PY
}

# One field out of a `_man_api` answer. Empty on anything unexpected.
_man_field() {
  python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    for k in sys.argv[1].split("."):
        d = d[k]
    print(d if not isinstance(d, bool) else str(d).lower())
except Exception:
    print("")' "$1"
}

# `grep -c`, never `grep -q`: under pipefail a match SIGPIPEs the writer and the
# pipeline reports failure on success (selffiles.sh carries the full account).
_man_log_has() {
  local svc="$1" re="$2" n
  n="$(compose logs "$svc" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -cE "$re" || true)"
  [ "${n:-0}" -gt 0 ]
}

harness_scenario_prepare() {
  rm -rf "$MAN_STATE"; mkdir -p "$MAN_STATE"; : >"$MAN_STATE/vars.sh"
  local svc
  for svc in $MAN_NODES; do harness_wait_healthy "$svc" 36; done

  if ! compose exec -T "$MAN_A" test -x "$MAN_CONSOLE" >/dev/null 2>&1; then
    echo "  ✗ $MAN_CONSOLE is not executable in the containers — build it first:"
    echo "    cargo build --release --features test-anchor,python"
    return 0
  fi

  # ── EACH NODE GETS AN OWNER ──────────────────────────────────────────────
  # Peering is owner-gated, so every node is claimed by its own person. Who
  # owns a registry node is not what this scenario is about; that it HAS an
  # owner is what lets it peer at all.
  local pin code claim claim_json token waited alias
  for svc in $MAN_NODES; do
    alias="ciris-operator-${svc}"
    compose exec -T "$svc" "$MAN_CONSOLE" identity create --backend software \
      --home /var/lib/ciris --key-id "$alias" >"$MAN_STATE/mint-$svc.out" 2>&1 || true
    pin=""; waited=0
    while [ "$waited" -lt 90 ]; do
      pin="$(compose exec -T "$svc" sh -c 'cat /var/lib/ciris/claim_pin 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
      [ -n "$pin" ] && break
      sleep 5; waited=$((waited + 5))
    done
    [ -z "$pin" ] && { echo "  ✗ $svc: no claim PIN after ${waited}s"; continue; }
    code="$(_man_api "$svc" GET /v1/federation/node-code | _man_field body.code | tr -d '\r\n[:space:]')"
    [ -z "$code" ] && { echo "  ✗ $svc: no node-code"; continue; }
    claim="$(compose exec -T "$svc" "$MAN_CONSOLE" claim --backend software \
               --home /var/lib/ciris --key-id "$alias" \
               --node-code "$code" --claim-pin "$pin" \
               --cohort-scope self --target-url http://127.0.0.1:4243 2>"$MAN_STATE/claim-$svc.err")"
    printf '%s\n' "$claim" >"$MAN_STATE/claim-$svc.out"
    claim_json="$(printf '%s\n' "$claim" | sed -n '/^{/,$p')"
    token="$(printf '%s' "$claim_json" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("access_token") or "")
except Exception: print("")')"
    printf 'MAN_TOKEN_%s=%s\n' "${svc//-/_}" "$token" >>"$MAN_STATE/vars.sh"
    echo "  $svc: claimed token=${token:+yes}"
    : >"$MAN_STATE/empty.json"; printf '{}' >"$MAN_STATE/empty.json"
    _man_api "$svc" POST /v1/federation/announce "$MAN_STATE/empty.json" >"$MAN_STATE/announce-$svc.json" || true
  done

  # ── EACH OWNER ACCEPTS THE ROOT ──────────────────────────────────────────
  # Edge roots a peer through its OWNER (CIRISEdge#659): two nodes are Rooted
  # to each other only when both owners accept a root in common. A first-run
  # claim binds the owner and does not write that acceptance; a restart does,
  # and so does a trust-root import, which is what runs here. Without it every
  # node is merely Attributed, and a row by a third party — a pipeline's
  # Contribution, the grant that blesses it — is withheld from every peer:
  # "the recipient is Attributed but not Rooted". The first runs of this ladder
  # stopped at `row_on_b` for exactly that reason.
  for svc in $MAN_NODES; do
    _man_load
    eval "token=\${MAN_TOKEN_${svc//-/_}:-}"
    compose exec -T "$svc" python - "$token" <<'PY' 2>/dev/null | sed "s/^/  $svc: /"
import json, sys, urllib.request, urllib.error
canon = "http://172.29.77.10:4243"
try:
    b = json.load(urllib.request.urlopen(canon + "/v1/federation/test-genesis-bundle", timeout=30))
except Exception as e:
    print("✗ registry A served no genesis bundle:", e); sys.exit(0)
req = urllib.request.Request("http://127.0.0.1:4243/v1/trust-root/import", method="POST",
    headers={"Authorization": "Bearer " + sys.argv[1], "Content-Type": "application/json"},
    data=json.dumps({"bundle": b["bundle"], "allegiance_from": canon}).encode())
try:
    r = urllib.request.urlopen(req, timeout=60); print("owner accepted the root:", r.read().decode()[:120])
except urllib.error.HTTPError as e:
    print("✗ import refused:", e.code, e.read().decode()[:240])
except Exception as e:
    print("✗ import failed:", e)
PY
  done

  # ── PEER THEM ────────────────────────────────────────────────────────────
  # The two registries with each other; the bystander with registry A only.
  #
  # `provenance:` IS IN THE PREFIX SET ON PURPOSE. persist projects a build
  # manifest row Global only when its author is the trust root itself; a
  # pipeline's row is Cohort, so it crosses only under a consent grant that
  # covers its dimension. Leave the prefix out and the row stays on the node it
  # was published to, silently — which is what `row_on_b` is there to catch.
  local a b pair peered=0 key
  for svc in $MAN_NODES; do
    _man_api "$svc" GET /v1/federation/test-blessed-self-record \
      | python3 -c 'import json,sys
try: print(json.dumps(json.load(sys.stdin)["body"]))
except Exception: pass' >"$MAN_STATE/record-$svc.json" 2>/dev/null || true
    key="$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["record"]["key_id"])
except Exception: print("")' "$MAN_STATE/record-$svc.json")"
    printf 'MAN_KEY_%s=%s\n' "${svc//-/_}" "$key" >>"$MAN_STATE/vars.sh"
    [ -n "$key" ] || echo "  ! $svc: no blessed self record"
  done
  for pair in "$MAN_A:$MAN_B" "$MAN_B:$MAN_A" "$MAN_A:$MAN_BYSTANDER" "$MAN_BYSTANDER:$MAN_A"; do
    a="${pair%%:*}"; b="${pair#*:}"
    [ -s "$MAN_STATE/record-$b.json" ] || continue
    python3 -c '
import json,sys
r=json.load(open(sys.argv[1]))
print(json.dumps({"peer_key_id": r["record"]["key_id"], "peer_key_record": r,
                  "attestation_prefixes": ["capacity:","ownership:","provenance:","self:delegates_to:","trace:"]}))' \
      "$MAN_STATE/record-$b.json" >"$MAN_STATE/peer-$a-$b.body.json" 2>/dev/null || continue
    _man_api "$a" POST /v1/federation/peering "$MAN_STATE/peer-$a-$b.body.json" >"$MAN_STATE/peering-$a-$b.json" || true
    if [ "$(_man_field status <"$MAN_STATE/peering-$a-$b.json")" = "200" ]; then
      peered=$((peered + 1))
    else
      echo "  ! peering $a->$b: $(head -c 240 "$MAN_STATE/peering-$a-$b.json" 2>/dev/null)"
    fi
  done
  echo "  peered $peered/4 directions"

  # ── THE PIPELINE ─────────────────────────────────────────────────────────
  # Run on the HOST, with the test root's seed read out of the compose file the
  # nodes were started from, so the pipeline is blessed by the root they anchor.
  local seed anchor bin
  seed="$(sed -n 's/^ *CIRIS_TEST_TRUST_ROOT_SEED: *"\(.*\)"/\1/p' docker-compose.yml | head -1)"
  anchor="$(sed -n 's/^ *CIRIS_TEST_TRUST_ROOT: *"\(.*\)"/\1/p' docker-compose.yml | head -1)"
  bin="../../target/release/examples/harness_ci_pipeline"
  if [ ! -x "$bin" ] || [ -n "$(find ../../examples/harness_ci_pipeline.rs -newer "$bin" -print -quit 2>/dev/null)" ]; then
    echo "── manifest: building the pipeline stand-in ──"
    ( cd ../.. && cargo build --release --features test-anchor,python --example harness_ci_pipeline 2>&1 | tail -2 )
  fi
  if ! CIRIS_TEST_TRUST_ROOT_SEED="$seed" CIRIS_TEST_TRUST_ROOT="$anchor" \
       CIRIS_HARNESS_EXTERNAL_PIPELINE="${MAN_EXTERNAL_PIPELINE:-}" \
       "$bin" "$MAN_STATE/ci" "$MAN_VERSION" >"$MAN_STATE/ci.out" 2>&1; then
    echo "  ✗ the pipeline stand-in failed: $(tail -3 "$MAN_STATE/ci.out")"
    return 0
  fi
  sed 's/^/  /' "$MAN_STATE/ci.out"
  python3 -c '
import json,sys
f=json.load(open(sys.argv[1]))
for who in ("blessed","unblessed","ceremony","external"):
    if not f.get(who): continue
    print("MAN_%s_VERSION=%s" % (who.upper(), f[who]["facts"]["binary_version"]))
    print("MAN_%s_SHA=%s" % (who.upper(), f[who]["facts"]["manifest_hash"]))
    print("MAN_%s_PIPELINE=%s" % (who.upper(), f[who]["pipeline_key_id"]))' \
    "$MAN_STATE/ci/facts.json" >>"$MAN_STATE/vars.sh"

  # ── PUBLISH, TO REGISTRY A ONLY ──────────────────────────────────────────
  # The unblessed one FIRST: if the door let it in, the blessed one arriving
  # after would not change that, and the ladder should see the door's own answer
  # to a stranger before anything else has been stored.
  echo "── manifest: the unblessed pipeline publishes to $MAN_A ──"
  _man_api "$MAN_A" POST /v1/builds "$MAN_STATE/ci/unblessed.json" >"$MAN_STATE/submit-unblessed.json" || true
  echo "  $(head -c 300 "$MAN_STATE/submit-unblessed.json")"
  echo "── manifest: the ceremony-blessed pipeline (accord role, no grant) publishes to $MAN_A ──"
  _man_api "$MAN_A" POST /v1/builds "$MAN_STATE/ci/ceremony.json" >"$MAN_STATE/submit-ceremony.json" || true
  echo "  $(head -c 300 "$MAN_STATE/submit-ceremony.json")"
  if [ -s "$MAN_STATE/ci/external.json" ]; then
    echo "── manifest: the EXTERNAL producer's Contribution is published to $MAN_A ──"
    _man_api "$MAN_A" POST /v1/builds "$MAN_STATE/ci/external.json" >"$MAN_STATE/submit-external.json" || true
    echo "  $(head -c 300 "$MAN_STATE/submit-external.json")"
  fi
  echo "── manifest: the blessed pipeline publishes to $MAN_A ──"
  _man_api "$MAN_A" POST /v1/builds "$MAN_STATE/ci/blessed.json" >"$MAN_STATE/submit-blessed.json" || true
  echo "  $(head -c 300 "$MAN_STATE/submit-blessed.json")"
  return 0
}

# ── 1 ───────────────────────────────────────────────────────────────────────
stage_rooted() {
  local svc n=0
  for svc in $MAN_NODES; do
    if _man_log_has "$svc" '[Tt][Rr][Uu][Ss][Tt] [Rr][Oo][Oo][Tt]'; then n=$((n+1)); fi
  done
  if [ "$n" -ge 3 ]; then echo "$n"; else echo 0; fi
}
HINT_rooted="a node never rooted to the test trust root — the anchor block is per persist/verify pair; run tests/anchor_block_verifies.rs after a substrate repin"
EXIT_rooted=30

# ── 2 ───────────────────────────────────────────────────────────────────────
stage_conferred() {
  local svc n=0
  for svc in $MAN_A $MAN_B; do
    if _man_log_has "$svc" 'registry slice CONFERRED'; then n=$((n+1)); fi
  done
  if [ "$n" -ge 2 ]; then echo "$n"; else echo 0; fi
}
HINT_conferred="a blessed node does not hold the registry slice. Read its 'registry slice WITHHELD' line: the walk is capability_roots_to_trusted_root(node, node, infra:attest), asked about the node's WIRE key — a withheld slice on a blessed node means the bless conferred infra:attest on the key record and the walk wants a grant it can find."
EXIT_conferred=31
DIAG_conferred() {
  local svc
  for svc in $MAN_A $MAN_B; do
    echo "· $svc:"; compose logs "$svc" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -E 'registry slice' | tail -2
  done
}

# ── 3 ───────────────────────────────────────────────────────────────────────
stage_holds_commons() {
  _man_load
  [ -n "${MAN_KEY_canonical:-}" ] || { echo 0; return; }
  if _man_log_has "$MAN_B" "commons blobs HELD.*${MAN_KEY_canonical}"; then echo 1; else echo 0; fi
}
HINT_holds_commons="registry B did not agree to hold commons blobs from registry A. Either it is not conferred the slice (see rung 2), or registry A's key is not on its holder roster — registry_boot.sh sets CIRIS_BLOB_COMMONS_HOLDERS from registry A's self record before the server starts; read its [registry_boot] line."
EXIT_holds_commons=32
DIAG_holds_commons() {
  compose logs "$MAN_B" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -E 'registry_boot|commons blobs|blob puller' | tail -4
}

# ── 4 ───────────────────────────────────────────────────────────────────────
stage_peered() {
  _man_load
  if [ -z "${MAN_KEY_canonical:-}" ] || [ -z "${MAN_KEY_node_a:-}" ]; then echo 0; return; fi
  local ab ba
  ab="$(harness_db_count "$MAN_A" federation_keys "key_id = '$MAN_KEY_node_a'")"
  ba="$(harness_db_count "$MAN_B" federation_keys "key_id = '$MAN_KEY_canonical'")"
  if [ "${ab:-0}" -gt 0 ] && [ "${ba:-0}" -gt 0 ]; then echo 2; else echo 0; fi
}
HINT_peered="the two registries did not admit each other. Read the 'peering' lines in the prepare output."
EXIT_peered=33

# ── 4b ──────────────────────────────────────────────────────────────────────
# Read on registry A, about BOTH owners: it is registry A that decides whether
# registry B is Rooted, and it decides from the rows it holds.
stage_owners_accept() {
  local n
  n="$(harness_db_count "$MAN_A" federation_attestations \
        "attestation_type = 'delegates_to' AND attesting_key_id LIKE 'ciris-operator-%' AND attested_key_id = 'test-accord-holder-0' AND cohort_scope = 'federation'")"
  if [ "${n:-0}" -ge 2 ]; then echo "$n"; else echo 0; fi
}
HINT_owners_accept="registry A does not hold both owners' acceptance of the trust root (delegates_to(owner → root) at federation). Until it does it treats registry B as Attributed, not Rooted, and withholds every third-party row from it. Read the 'owner accepted the root' lines in the prepare output."
EXIT_owners_accept=40

# ── 5 ───────────────────────────────────────────────────────────────────────
stage_refused() {
  [ -s "$MAN_STATE/submit-unblessed.json" ] || { echo 0; return; }
  local status token
  status="$(_man_field status <"$MAN_STATE/submit-unblessed.json")"
  token="$(_man_field body.error <"$MAN_STATE/submit-unblessed.json")"
  if [ "$status" = "403" ] && [ "$token" = "pipeline_not_blessed" ]; then echo 1; else echo 0; fi
}
HINT_refused="the door did not refuse an unblessed pipeline as pipeline_not_blessed. A 201 here is the finding that matters most: a valid signature bought a build. Any other refusal means the unblessed submission never reached the blessing check — read submit-unblessed.json."
EXIT_refused=34
DIAG_refused() { head -c 400 "$MAN_STATE/submit-unblessed.json" 2>/dev/null; echo; }

# ── 6 ───────────────────────────────────────────────────────────────────────
stage_admitted() {
  [ -s "$MAN_STATE/submit-blessed.json" ] || { echo 0; return; }
  if [ "$(_man_field status <"$MAN_STATE/submit-blessed.json")" = "201" ]; then echo 1; else echo 0; fi
}
HINT_admitted="registry A refused the BLESSED pipeline. The refusal token says which check: unknown_pipeline = persist's role-admission gate refused the pipeline's key record; pipeline_not_blessed = the record was stored and the capability walk does not see infra:attest from a root this node accepts; substrate_error = persist refused the row or the blob."
EXIT_admitted=35
DIAG_admitted() { head -c 500 "$MAN_STATE/submit-blessed.json" 2>/dev/null; echo; }

# ── 6b ──────────────────────────────────────────────────────────────────────
# The production shape. The door must admit it AND say which authority did.
stage_ceremony_admitted() {
  [ -s "$MAN_STATE/submit-ceremony.json" ] || { echo 0; return; }
  if [ "$(_man_field status <"$MAN_STATE/submit-ceremony.json")" = "201" ] \
     && [ "$(_man_field body.standing <"$MAN_STATE/submit-ceremony.json")" = "accord_role" ]; then echo 1; else echo 0; fi
}
HINT_ceremony_admitted="registry A refused a pipeline blessed the way the accord's CI-key ceremony blesses one (infra:attest co-scrubbed onto the key record, no grant), or admitted it under some other standing. unknown_pipeline = persist's infra:attest admission gate refused the record; pipeline_not_blessed = the record is stored and is_infra_attest_effective reads false, which means the role did not land in the row's roles."
EXIT_ceremony_admitted=41
DIAG_ceremony_admitted() { head -c 500 "$MAN_STATE/submit-ceremony.json" 2>/dev/null; echo; }

# Registry B serves the ceremony-blessed build with its bytes. Here the standing
# is not a row that has to replicate: it rides the pipeline's own key record.
stage_ceremony_on_b() {
  _man_load
  [ -n "${MAN_CEREMONY_VERSION:-}" ] || { echo 0; return; }
  local out
  out="$(_man_api "$MAN_B" GET "/v1/builds/${MAN_CEREMONY_VERSION}")"
  if [ "$(printf '%s' "$out" | _man_field status)" = "200" ] \
     && [ "$(printf '%s' "$out" | _man_field body.manifest_held)" = "true" ] \
     && [ "$(printf '%s' "$out" | _man_field body.standing.standing)" = "accord_role" ]; then echo 1; else echo 0; fi
}
HINT_ceremony_on_b="registry B does not serve the ceremony-blessed build with its bytes under accord_role standing. The Contribution and the pipeline's key record both have to cross, and registry B's own is_infra_attest_effective has to read the role off the record it received."
EXIT_ceremony_on_b=42

stage_external_admitted() {
  [ -s "$MAN_STATE/submit-external.json" ] || { echo 0; return; }
  if [ "$(_man_field status <"$MAN_STATE/submit-external.json")" = "201" ]; then echo 1; else echo 0; fi
}
HINT_external_admitted="registry A refused the external producer's Contribution. The refusal token is the finding: it names the first thing that producer and this door disagree on."
EXIT_external_admitted=43
DIAG_external_admitted() { head -c 600 "$MAN_STATE/submit-external.json" 2>/dev/null; echo; }

stage_external_on_b() {
  _man_load
  [ -n "${MAN_EXTERNAL_SHA:-}" ] || { echo 0; return; }
  local got
  got="$(compose exec -T "$MAN_B" python -c '
import hashlib, sys, urllib.request
try:
    print(hashlib.sha256(urllib.request.urlopen("http://127.0.0.1:4243/v1/builds/manifest/" + sys.argv[1], timeout=30).read()).hexdigest())
except Exception:
    print("")' "$MAN_EXTERNAL_SHA" 2>/dev/null | tr -d '[:space:]')"
  if [ "$got" = "$MAN_EXTERNAL_SHA" ]; then echo 1; else echo 0; fi
}
HINT_external_on_b="registry B does not serve the external producer's manifest bytes. Same causes as ceremony_on_b."
EXIT_external_on_b=44

# A node's answer for the blessed build. Echoes "<status> <manifest_held>".
_man_build_on() {
  _man_load
  local out
  out="$(_man_api "$1" GET "/v1/builds/${MAN_BLESSED_VERSION:-$MAN_VERSION}")"
  printf '%s %s\n' "$(printf '%s' "$out" | _man_field status)" "$(printf '%s' "$out" | _man_field body.manifest_held)"
}

# ── 7 ───────────────────────────────────────────────────────────────────────
stage_served_on_a() {
  local ans; ans="$(_man_build_on "$MAN_A")"
  if [ "$ans" = "200 true" ]; then echo 1; else echo 0; fi
}
HINT_served_on_a="registry A admitted the Contribution and does not serve the build with its bytes. The read re-verifies: signature, dimension, and the pipeline's blessing from a root this node accepts."
EXIT_served_on_a=36

# ── 8 ───────────────────────────────────────────────────────────────────────
stage_row_on_b() {
  local ans; ans="$(_man_build_on "$MAN_B")"
  case "$ans" in "200 "*) echo 1;; *) echo 0;; esac
}
HINT_row_on_b="registry B does not serve the build. If owners_accept is red, start there. Otherwise two different causes, told apart by the evidence block: (1) the Contribution row never replicated — the consent grant between the registries does not cover 'provenance:', or the pipeline's key record did not cross so the row was refused as unattributable; (2) the row is there and registry B's own walk does not see the pipeline as blessed."
EXIT_row_on_b=37
DIAG_row_on_b() {
  _man_load
  echo "· $MAN_B rows by the pipeline: $(harness_db_count "$MAN_B" federation_attestations "attesting_key_id = '${MAN_BLESSED_PIPELINE:-}'")"
  echo "· $MAN_B holds the pipeline's key: $(harness_db_count "$MAN_B" federation_keys "key_id = '${MAN_BLESSED_PIPELINE:-}'")"
  echo "· $MAN_A rows by the pipeline: $(harness_db_count "$MAN_A" federation_attestations "attesting_key_id = '${MAN_BLESSED_PIPELINE:-}'")"
  compose logs "$MAN_B" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -E 'build manifest row ignored' | tail -3
}

# ── 9 ───────────────────────────────────────────────────────────────────────
# The bytes, hashed on the way out. `manifest_held: true` is the node's own
# word; the SHA-256 of what it returns is the measurement.
stage_blob_on_b() {
  _man_load
  [ -n "${MAN_BLESSED_SHA:-}" ] || { echo 0; return; }
  local got
  got="$(compose exec -T "$MAN_B" python -c '
import hashlib, sys, urllib.request
try:
    print(hashlib.sha256(urllib.request.urlopen("http://127.0.0.1:4243/v1/builds/manifest/" + sys.argv[1], timeout=30).read()).hexdigest())
except Exception:
    print("")' "$MAN_BLESSED_SHA" 2>/dev/null | tr -d '[:space:]')"
  if [ "$got" = "$MAN_BLESSED_SHA" ]; then echo 1; else echo 0; fi
}
HINT_blob_on_b="registry B has the Contribution and not the bytes. The pull is edge's: the row names the blob in evidence_refs, the puller needs a holder (registry A's holds_bytes claim has to have crossed) and the store gate needs all three axes — registry A on the commons holder roster, this node in the audience, and commons consent. Read the blob lines in the evidence block."
EXIT_blob_on_b=38
DIAG_blob_on_b() {
  _man_load
  echo "· $MAN_B federation_blobs: $(harness_db_count "$MAN_B" federation_blobs "")"
  echo "· $MAN_B holds_bytes rows: $(harness_db_count "$MAN_B" federation_attestations "attestation_type LIKE 'holds_bytes:%'")"
  compose logs "$MAN_B" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -iE 'blob' | grep -viE 'blob puller spawned' | tail -8
}

# ── 10 ──────────────────────────────────────────────────────────────────────
# Passes only once the POSITIVE control holds: a node that serves nothing at all
# would trivially not serve the unblessed build either.
stage_unblessed_is_nowhere() {
  _man_load
  [ -n "${MAN_UNBLESSED_VERSION:-}" ] || { echo 0; return; }
  if [ -f "$MAN_STATE/unblessed-served" ]; then echo 0; return; fi
  local svc status
  for svc in $MAN_A $MAN_B; do
    status="$(_man_api "$svc" GET "/v1/builds/${MAN_UNBLESSED_VERSION}" | _man_field status)"
    if [ "$status" = "200" ]; then : >"$MAN_STATE/unblessed-served"; echo 0; return; fi
    if [ "$status" != "404" ]; then echo 0; return; fi
  done
  local ans; ans="$(_man_build_on "$MAN_A")"
  case "$ans" in "200 "*) echo 1;; *) echo 0;; esac
}
HINT_unblessed_is_nowhere="a node served the unblessed pipeline's build (latched for the run), or the positive control is not up yet — registry A must serve the BLESSED build before 'nobody serves the unblessed one' means anything."
EXIT_unblessed_is_nowhere=39

harness_scenario_evidence() {
  _man_load
  local svc
  echo "· pipeline (blessed):   ${MAN_BLESSED_PIPELINE:-?}  version ${MAN_BLESSED_VERSION:-?}  manifest ${MAN_BLESSED_SHA:-?}"
  echo "· pipeline (unblessed): ${MAN_UNBLESSED_PIPELINE:-?}  version ${MAN_UNBLESSED_VERSION:-?}"
  for svc in $MAN_NODES; do
    echo "· $svc: build=$(_man_build_on "$svc") rows_by_pipeline=$(harness_db_count "$svc" federation_attestations "attesting_key_id = '${MAN_BLESSED_PIPELINE:-}'") blobs=$(harness_db_count "$svc" federation_blobs "")"
  done
  echo "· $MAN_B provenance as it serves it:"
  _man_api "$MAN_B" GET "/v1/builds/${MAN_BLESSED_VERSION:-$MAN_VERSION}" | python3 -c '
import json,sys
try:
    b=json.load(sys.stdin)["body"]
    for e in b["federation_provenance"]["attestations_consumed"]:
        print("   ", e["dimension"], "|", e["evidence_summary"])
except Exception as e:
    print("    (none)")' || true
}
