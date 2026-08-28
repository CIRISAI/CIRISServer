//! **The boundary** — the one forward gate that is RED BY DESIGN, the one
//! external-fact gate, and the live watcher that keeps both honest.
//!
//! This module is the whole of the ladder's non-hermetic surface, kept small and
//! kept separate on purpose. The two `#[ignore]`d gates in it are the only two
//! entries on [`crate::ladder::IGNORE_ALLOWLIST`] — so
//! [`crate::ladder::gate0_no_gate_is_silently_ignored`] fails the moment a third
//! one appears anywhere in the suite.
//!
//! The previous ladder's ignored gates rotted because nothing watched them:
//! "persist v10 ships and we re-pin" sat ignored through twenty releases. So each
//! forward gate here has a LIVE counterpart —
//! [`gate0_no_forward_rung_has_quietly_become_satisfiable`] — which runs on every
//! `cargo test --test release_gates` and FAILS the moment the forward condition
//! is met. An ignored gate that has come true cannot stay ignored.
//!
//! **That mechanism has now fired once, which is why this module is one gate
//! smaller.** `gate_trace_flow_over_replication` lived here, RED against
//! CIRISEdge#455: a sealed `trace:*` did not reach the canonical over an
//! anti-entropy round. Persist v30.1.0 / edge v15.18.3 closed the last cause
//! (CIRISPersist#610), the round test flipped its soft frontier to an `assert!`,
//! and the watcher below went red the same commit — not months later. The rung
//! now runs live as [`crate::planes::gate_trace_flow_over_replication`]. The
//! watcher never got to be wrong about it, which is the whole design.

use std::path::PathBuf;

use crate::ladder::{blocked, repo};

// ─────────────────────────────────────────────────────────────────────────────
// The forward predicates, evaluated in exactly ONE place each
// ─────────────────────────────────────────────────────────────────────────────

/// 0.6's defining surface: the registry that bootstraps the canonical mesh.
fn registry_surface_present() -> bool {
    let src = repo().join("src");
    src.join("registry.rs").exists() || src.join("registry").is_dir()
}

// ─────────────────────────────────────────────────────────────────────────────
// The live watcher
// ─────────────────────────────────────────────────────────────────────────────

/// **The watcher.** Runs always; fails when a forward gate has come true.
///
/// This is the ratchet that the previous ladder lacked. Its gates went stale
/// silently because being ignored and being unmet are indistinguishable from the
/// outside — so a requisite that had been satisfied for twenty releases still
/// read as "pending". Here, satisfying a forward condition BREAKS the build until
/// someone promotes the gate to a live one and removes it from the allowlist.
#[test]
fn gate0_no_forward_rung_has_quietly_become_satisfiable() {
    let mut ripe: Vec<&str> = Vec::new();
    if registry_surface_present() {
        ripe.push(
            "  `gate_registry_surface_present` — src/registry.rs now EXISTS. This is the 0.6\n\
             \x20   boundary: the +registry surface is built. Promote the gate (drop its\n\
             \x20   #[ignore] and its IGNORE_ALLOWLIST entry) and decide deliberately whether\n\
             \x20   this cut is still 0.5.",
        );
    }
    assert!(
        ripe.is_empty(),
        "\n\
         🔔 RELEASE LADDER — a forward gate has come true and is still switched off.\n\
         \n\
         Unsafe to ship: an #[ignore]d gate whose condition is now MET reports nothing,\n\
         and 'pending forever' is exactly how the previous ladder died. Reality moved;\n\
         the ladder must move with it in the same commit.\n\
         \n\
         {}\n",
        ripe.join("\n\n"),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The forward gate — the 0.6 boundary
// ─────────────────────────────────────────────────────────────────────────────

/// **The 0.6 boundary, carried forward from the previous ladder unchanged.**
///
/// It is the one gate of that suite that still means exactly what it says: 0.6 is
/// the registry fold, and 0.6 must not tag until `src/registry.rs` exists. While
/// we are on 0.5.X it is correctly RED and correctly ignored.
#[test]
#[ignore = "RED BY DESIGN — the 0.6 boundary: `src/registry.rs` does not exist while we are on 0.5.X. Watched live by gate0_no_forward_rung_has_quietly_become_satisfiable. Run with --include-ignored."]
fn gate_registry_surface_present() {
    assert!(
        registry_surface_present(),
        "\n\
         🚫 RELEASE GATE [0.6-boundary] — DO NOT TAG 0.6.\n\
         \n\
         Unsafe to ship as 0.6: `src/registry.rs` is absent, so the +registry surface —\n\
         the thing that bootstraps the canonical mesh and the whole content of the 0.6\n\
         fold — is not built. A 0.6 tag without it is a version number claiming a\n\
         capability the binary does not have, and downstream floors are written against\n\
         the number.\n\
         \n\
         (This is expected and correct on 0.5.X. It is here so 0.6 cannot be tagged by\n\
         momentum.)\n"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The external-fact plane — the whole of it
// ─────────────────────────────────────────────────────────────────────────────

fn node_url(which: &str) -> Option<String> {
    std::env::var(format!("CIRIS_GATE_NODE_{which}"))
        .ok()
        .filter(|s| !s.trim().is_empty())
}

fn http_get(url: &str) -> Result<(u16, String), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(6))
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, body))
    })
}

fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut it = core.split('.');
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

/// **The one external-fact gate: the peers are on the floor this cut ships.**
///
/// This is the only rung in the ladder that cannot be answered from the tree, and
/// it is here because the fact genuinely is a release requisite: a mesh whose
/// bridge nodes run an older floor will refuse rows this cut emits, and the
/// refusal presents as "the mesh is quiet".
///
/// Its absence reads **BLOCKED, never PASSED** — [`blocked`] panics with wording
/// chosen so an un-evaluable gate can never be mistaken for a satisfied one. That
/// is the whole lesson of the ladder this replaced: its evidence gates defaulted
/// to silence, and silence read as fine.
///
/// Why `/v1/health`.`data.version` and not `/health`: a node may wrap ciris-server
/// in an adapter (CIRISStatus = ciris-server + StatusAdapter) whose own `/health`
/// reports the WRAPPER's version. The adapter does not override `/v1/health`, so
/// that route reports the EMBEDDED ciris-server version — the floor signal, read
/// uniformly across a bare node and a wrapped one.
#[test]
#[ignore = "RED BY DESIGN — external fact: needs a reachable peer (CIRIS_GATE_NODE_A/_B). BLOCKED, never passed, without one. Run with --include-ignored."]
fn gate_peer_nodes_on_the_shipping_floor() {
    let floor = parse_semver(env!("CARGO_PKG_VERSION")).expect("our own version parses");
    let mut probed = 0usize;
    for which in ["A", "B"] {
        let Some(base) = node_url(which) else {
            blocked(
                "peer-nodes-on-floor",
                &format!(
                    "CIRIS_GATE_NODE_{which} is unset, so whether peer {which} runs this cut's\n\
                     floor is UNKNOWN. Unknown is not 'yes'. A peer on an older floor refuses\n\
                     rows this cut emits, and that refusal presents as a quiet mesh rather than\n\
                     as an error — which is the 2026-08-03 shape exactly.\n\
                     \n\
                     Set CIRIS_GATE_NODE_{which}=<base-url> and re-run, or record explicitly\n\
                     that this release ships without confirming the peer floor."
                ),
            );
        };
        let url = format!("{}/v1/health", base.trim_end_matches('/'));
        let (status, body) = match http_get(&url) {
            Ok(r) => r,
            Err(e) => blocked(
                "peer-nodes-on-floor",
                &format!(
                    "{url} is UNREACHABLE ({e}), so peer {which}'s floor is unknown. An\n\
                     unreachable peer is not a peer on the right floor — and it is not a peer\n\
                     on the wrong one either. Nothing was measured."
                ),
            ),
        };
        assert_eq!(
            status, 200,
            "\n\
             🚫 RELEASE GATE [peer-nodes-on-floor] — DO NOT TAG.\n\
             Unsafe to ship: {url} answered {status}. A bridge node that cannot answer its own\n\
             health route is not a node this cut can be released against.\n"
        );
        let v: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("{url} body is not JSON ({e}) — peer floor UNKNOWN"));
        let ver = v
            .get("data")
            .and_then(|d| d.get("version"))
            .or_else(|| v.get("version"))
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("{url} carries no data.version — peer floor UNKNOWN"));
        let got = parse_semver(ver).unwrap_or_else(|| panic!("unparseable version {ver:?}"));
        assert!(
            got >= floor,
            "\n\
             🚫 RELEASE GATE [peer-nodes-on-floor] — DO NOT TAG.\n\
             \n\
             Unsafe to ship: peer {which} runs {ver}, below this cut's floor {floor:?}. It will\n\
             refuse rows this cut emits, and the refusal is silent from our side — the plane\n\
             just goes quiet. Upgrade the peer first; a cut released into a mesh that cannot\n\
             read it is a cut nobody can roll back from safely.\n"
        );
        probed += 1;
    }
    assert_eq!(probed, 2, "both bridge nodes must be probed");
}

/// The evidence-file mechanism is GONE, and must stay gone.
///
/// Ten of the previous ladder's nineteen tests gated on
/// `tests/release_gates/evidence/stageN.json` — files an operator had to remember
/// to write, and never did. The directory held only `.tsv`. So the gates carrying
/// the most weight defaulted to silence.
///
/// This is not a style rule. An operator-dropped JSON file is an ASSERTION BY A
/// HUMAN that something is true, checked by nothing: it passes when someone
/// writes it, whether or not the fact holds, and it fails identically whether the
/// fact is false or the human was busy. Where an external fact really is the gate,
/// it must be PROBED (see above) — measured, or BLOCKED.
#[test]
fn gate0_no_gate_depends_on_an_operator_dropped_evidence_file() {
    // The needles are ASSEMBLED rather than written, so this file does not
    // contain them verbatim and the scan below cannot match its own source. A
    // gate that has to exempt itself by filename would stop covering the module
    // it lives in — which is one of the six modules it must cover.
    let ev: String = ['e', 'v', 'i', 'd', 'e', 'n', 'c', 'e'].iter().collect();
    let dir_needle = format!("{ev}/");
    let fn_needle = format!("fn {ev}(");

    let evidence_dir: PathBuf = repo().join("tests/release_gates").join(&ev);
    assert!(
        !evidence_dir.exists(),
        "\n\
         🚫 RELEASE LADDER — the evidence-file mechanism is back.\n\
         \n\
         Unsafe to ship: {} exists. A gate that reads an operator-dropped JSON file is a\n\
         human assertion checked by nothing — it passes because someone wrote a file, not\n\
         because the fact holds, and it is silent in exactly the case that matters. Ten of\n\
         nineteen gates in the ladder this replaced worked that way, and not one evidence\n\
         file was ever written.\n\
         \n\
         Probe the fact, or mark the gate BLOCKED.\n",
        evidence_dir.display(),
    );

    let mut readers: Vec<String> = Vec::new();
    let dir = repo().join("tests/release_gates");
    for entry in std::fs::read_dir(&dir).expect("tests/release_gates readable") {
        let p = entry.expect("dir entry").path();
        if p.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&p).expect("gate source");
        for (n, line) in src.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains(&dir_needle) || code.contains(&fn_needle) {
                readers.push(format!(
                    "  {}:{}",
                    p.file_name().and_then(|f| f.to_str()).unwrap_or_default(),
                    n + 1
                ));
            }
        }
    }
    assert!(
        readers.is_empty(),
        "\n\
         🚫 RELEASE LADDER — a gate reads an operator-dropped evidence file.\n{}\n",
        readers.join("\n"),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The index must offer a wheel a NON-DESKTOP consumer can resolve
// ─────────────────────────────────────────────────────────────────────────────

/// The `ciris-client` requirement pinned in `pyproject.toml`, as `(name, version)`.
/// The client requirement's name and FLOOR version.
///
/// 0.5.192 moved this from `==X` to `>=FLOOR,<BOUND`. The floor is what matters
/// to every gate here: it is the oldest version a consumer may resolve, so it is
/// the one whose wheel matrix and whose bundle must both be checked. The upper
/// end of the range is exercised by CI, which installs the range and gets the
/// latest.
///
/// Reads through `tools/client_pin.py --floor` rather than re-parsing the
/// requirement here — that script is the ONE home of this version string, and
/// re-spelling the parse is how five copies accumulated the first time.
fn pinned_client() -> Option<(String, String)> {
    let out = std::process::Command::new("python3")
        .arg(repo().join("tools/client_pin.py"))
        .arg("--floor")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let floor = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!floor.is_empty()).then(|| ("ciris-client".to_owned(), floor))
}

/// **The pinned client must publish a wheel a non-desktop consumer can resolve.**
///
/// CIRISServer#493: 0.5.189 could not be installed on Android at all. The
/// unconditional `ciris-client==` pin met a wheel matrix of four PLATFORM wheels
/// and no `py3-none-any`, so a pip targeting Android matched no tag, fell back to
/// the last version that had one, and the `==` pin rejected it.
///
/// Nothing on this side could see that. The pin gate compares version STRINGS,
/// and pip on a desktop CI runner resolves the manylinux wheel and is happy. The
/// universal wheel had silently vanished at 0.5.188 and went unnoticed for two
/// releases, because nothing depended on the client until #471 made it a hard
/// requirement.
///
/// # The lag this is written around
///
/// This gate's own first run was a FALSE NEGATIVE. Checking the JSON API moments
/// after a publish reported four files when five had been uploaded — the
/// universal wheel was still propagating — and I concluded from that snapshot
/// that the fix had not landed. It had.
///
/// So: retry with backoff, and read the **simple index** rather than the JSON
/// API. They are separately cached, and the simple index is the surface `pip`
/// itself resolves against — which is the actual question ("can a consumer get a
/// wheel?"), not a proxy for it. A gate that answers a different question from
/// the one it claims is the shape this ladder exists to refuse.
///
/// Absence reads **BLOCKED, never PASSED**: an unreachable index means the
/// question was not answered, and this repo has paid six times for a gate that
/// passed because it could not look.
#[test]
#[ignore = "RED BY DESIGN — external fact: reads the PyPI simple index for the pinned ciris-client. BLOCKED, never passed, when the index is unreachable. Run with --include-ignored."]
fn gate_pinned_client_offers_a_non_desktop_wheel() {
    let Some((name, version)) = pinned_client() else {
        blocked(
            "client-wheel-resolvable",
            "no `ciris-client==` requirement found in pyproject.toml — this gate cannot \
             pass by finding nothing to check",
        );
    };
    let url = format!("https://pypi.org/simple/{name}/");

    // Backoff across the publish window. A tag's wheels land over tens of
    // seconds, and a gate that samples once during that window reports a real
    // release as broken.
    let mut last_err = String::new();
    for (attempt, wait) in [0u64, 5, 15, 30].into_iter().enumerate() {
        if wait > 0 {
            std::thread::sleep(std::time::Duration::from_secs(wait));
        }
        match http_get(&url) {
            Ok((200, body)) => {
                let dist = name.replace('-', "_");
                let want = format!("{dist}-{version}-py3-none-any.whl");
                if body.contains(&want) {
                    return;
                }
                // NOT-PUBLISHED and PUBLISHED-WITHOUT-THE-UNIVERSAL-WHEEL are
                // different states and must not share a message. My own mutation
                // test caught this: pinning a version that does not exist reported
                // "publishes no py3-none-any wheel", which sends a reader to
                // CIRISClient's wheel matrix for a version that was never cut.
                let any_file_for_version = format!("{dist}-{version}-");
                last_err = if body.contains(&any_file_for_version) {
                    format!("published-without-universal (attempt {})", attempt + 1)
                } else {
                    format!("not-published (attempt {})", attempt + 1)
                };
            }
            Ok((code, _)) => last_err = format!("HTTP {code} from {url}"),
            Err(e) => last_err = format!("{url}: {e}"),
        }
    }

    if last_err.starts_with("not-published") {
        panic!(
            "\n\
             🚫 RELEASE GATE [client-wheel-resolvable] — DO NOT TAG.\n\
             \n\
             `{name}=={version}` is not on the index at all. The pin names a version\n\
             CIRISClient has not published, so EVERY consumer fails to resolve it, not\n\
             just the off-desktop ones.\n\
             \n\
             This is the expected state while a paired cut is in flight — the server\n\
             pins the version it will ship with and the client publishes it — and it\n\
             clears itself the moment they cut. It is a true red, not a broken gate.\n"
        );
    }
    if last_err.starts_with("published-without-universal") {
        panic!(
            "\n\
             🚫 RELEASE GATE [client-wheel-resolvable] — DO NOT TAG.\n\
             \n\
             The pinned `{name}=={version}` publishes no `py3-none-any` wheel, so a pip\n\
             targeting a platform you do not build for — Android via Chaquopy, iOS —\n\
             matches NO tag. It then falls back to the newest version that has one, and\n\
             the `==` pin rejects that, so the install fails outright rather than\n\
             degrading (CIRISServer#493).\n\
             \n\
             Nothing else here can see this: the pin gate compares version strings, and\n\
             pip on a desktop runner resolves the platform wheel and is happy.\n\
             \n\
             {last_err}\n\
             \n\
             Fix in CIRISClient by splitting the ARTIFACT, not the dependency: platform\n\
             wheels carry the desktop uber-jar, `py3-none-any` carries none. Wheel-tag\n\
             preference is evaluated by the INSTALLING pip against its own target tags,\n\
             so desktop takes its platform wheel and never sees `any` — no environment\n\
             marker, and nothing evaluated on the build host.\n"
        );
    }
    blocked(
        "client-wheel-resolvable",
        &format!(
            "could not read the PyPI simple index after 4 attempts over ~50s, so whether \
             {name}=={version} is installable off-desktop is UNKNOWN — which is not the \
             same as fine. Last: {last_err}"
        ),
    );
}

/// **The floor must resolve every id this server emits.**
///
/// The gate that makes `>=` an honest claim rather than a hope. It installs the
/// FLOOR version into a throwaway venv and runs the localization guard against
/// its bundle — the same guard CI runs against whatever the range resolves to,
/// pointed at the other end of the range.
///
/// # Why this exists at all
///
/// The exact pin it replaces had one genuine virtue, written into pyproject at
/// the time: an upstream bundle change could not turn a green tree red with no
/// commit here to explain it. A range gives that up in the other direction — a
/// version inside the range could be missing an id this server emits, and the
/// failure would land on a user's fresh install while CI stayed green against a
/// different version.
///
/// So the range is tested at BOTH ends. An untested bound is a guess with a
/// version number on it.
///
/// Measured before it was claimed: the floor is 0.5.190, and the guard passes
/// against 0.5.188 too — the ids resolve three versions below where the equality
/// pin sat. The floor is 0.5.190 rather than 0.5.188 because 0.5.188 publishes no
/// `py3-none-any`, so a lower floor would let Android resolve it and reproduce
/// CIRISServer#493. THE WHEEL MATRIX SETS THE FLOOR, NOT THE API.
#[test]
#[ignore = "RED BY DESIGN — external fact: installs the client floor from PyPI into a temp venv. BLOCKED, never passed, when the index or python3 is unavailable. Run with --include-ignored."]
fn gate_client_floor_resolves_every_id() {
    let Some((name, floor)) = pinned_client() else {
        blocked(
            "client-floor-ids",
            "could not read the client floor from tools/client_pin.py — the range's lower \
             bound is what this gate exists to verify, so not knowing it is BLOCKED, not \
             a pass",
        );
    };
    let venv = std::env::temp_dir().join(format!("ciris-floor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&venv);

    let mk = std::process::Command::new("python3")
        .args(["-m", "venv"])
        .arg(&venv)
        .output();
    match mk {
        Ok(o) if o.status.success() => {}
        other => blocked(
            "client-floor-ids",
            &format!("could not create a venv to install the floor into: {other:?}"),
        ),
    }
    let pip = venv.join("bin/pip");
    let install = std::process::Command::new(&pip)
        .args(["install", "-q", &format!("{name}=={floor}")])
        .output();
    match install {
        Ok(o) if o.status.success() => {}
        other => blocked(
            "client-floor-ids",
            &format!(
                "could not install {name}=={floor} — whether the floor resolves every id \
                 is UNKNOWN, which is not the same as fine: {other:?}"
            ),
        ),
    }

    let guard = std::process::Command::new(venv.join("bin/python3"))
        .arg(repo().join("tools/check_server_localization.py"))
        .current_dir(repo())
        .output()
        .expect("run the localization guard against the floor bundle");
    let _ = std::fs::remove_dir_all(&venv);

    assert!(
        guard.status.success(),
        "\n\
         🚫 RELEASE GATE [client-floor-ids] — DO NOT TAG.\n\
         \n\
         The declared floor {name}=={floor} does NOT resolve every id this server emits.\n\
         A consumer resolving the bottom of the range would install a client whose\n\
         bundle is missing strings this node sends, and the failure would surface as\n\
         untranslated or absent UI on their machine rather than here.\n\
         \n\
         Raise the floor in pyproject.toml to the oldest client that passes, and say in\n\
         the comment WHY that version — the floor is a claim about compatibility and it\n\
         should be traceable to the thing that made it true.\n\
         \n\
         {}\n{}\n",
        String::from_utf8_lossy(&guard.stdout),
        String::from_utf8_lossy(&guard.stderr)
    );
}
