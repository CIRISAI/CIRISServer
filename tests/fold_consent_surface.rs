//! The in-fold consent surface — pinned so it cannot silently regress.
//!
//! # The defect this exists for
//!
//! A production wizard running inside the fold called
//! `GET /v1/accord/canonical-servers` and got a **404**, then never authored
//! consent. Two separate causes, and the second is the durable one:
//!
//!   * the path was wrong — it is `/v1/accord/canonical/servers`;
//!   * **no HTTP path could have worked.** The embedded agent boots through
//!     `start_and_hold`, which mounts no router at all. Every owner-gated route
//!     is mounted in `serve_with_adapter`, the compose path. Inside the fold,
//!     `POST /v1/federation/consent` 404s by construction.
//!
//! The wizard reached for HTTP because our own docstring told it to: it said
//! *"production consent is exclusively the owner-gated POST
//! /v1/federation/consent"*, which stopped being true in 0.5.147 and was still
//! there in 0.5.149. **A stale doc is an instrument that reports the wrong
//! branch** — the same class as everything in `FSD/RCA_TRACE_PLANE_2026-07-31.md`.
//!
//! # What is deliberately NOT here
//!
//! There is no `consent_to_canonicals()` convenience. It was written and
//! reverted: it decided both *which* peers ("all canonicals") and *what* policy
//! ("our defaults"), and neither is ours to decide. The exhaustive consent form
//! is the agent's — *"traces to canonicals blessed by a trust root I trust"*,
//! *"medical data to medical providers my providers trust"* — and it changes per
//! deployment. Collapsing peer selection into the call makes every one of those
//! unreachable and pushes the caller straight back to composing by hand, around
//! a function that no longer fits.
//!
//! So the surface stays decomposed: **enumerate → filter on your own predicate →
//! author per peer.** Two calls when our default policy suits you, three when it
//! does not.

use std::path::Path;

fn lib_rs() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("src/lib.rs must be readable")
}

/// The fold must be able to author consent WITHOUT an HTTP router.
#[test]
fn author_federation_consent_is_exported_to_the_fold() {
    let src = lib_rs();
    assert!(
        src.contains(r#"name = "author_federation_consent""#),
        "the fold's only consent path must stay exported from the pymodule — without it an \
         embedded agent has no way to author consent at all, because start_and_hold mounts no \
         HTTP router"
    );
    assert!(
        src.contains("wrap_pyfunction!(py_author_federation_consent"),
        "exported is not enough — it must also be REGISTERED on the module, or the wizard sees \
         AttributeError and falls back to the HTTP path that 404s"
    );
}

/// **CIRISConstitution#46 — the second half of the consent.**
///
/// The replication grant lets a peer HOLD our traces. Only the `analyze` grant
/// lets it SCORE them: `check_capacity_consent_admission` refuses a
/// federation-tier `capacity:*` claim about S from P unless a live `analyze`
/// consent S → P sits in **P's own** corpus. Different dimension
/// (`consent:state:granted:*` vs `consent:replication:*`), different edge
/// direction — authoring one does not imply the other.
///
/// `POST /v1/federation/consent` has taken an `analyze` flag since #331 ask 1.
/// The fold's path could not author the row under ANY argument, because the
/// parameter did not exist — so the two consent paths were asymmetric and the
/// one every embedded agent must use was the incomplete one.
///
/// Measured on the production canonical, 2026-08-01: **240**
/// `consent:replication:v1` rows replicated in from **240 distinct** peers,
/// **184** trace_events, and **ZERO** `consent:state:*` rows of any kind. Every
/// one of those peers consented to send traces; not one could consent to be
/// scored. The carrier was never the problem — all 240 arrived remotely — the
/// producer was absent.
#[test]
fn the_fold_can_author_the_cc46_analyze_grant() {
    let src = lib_rs();
    let sig = src
        .lines()
        .find(|l| l.contains(r#"name = "author_federation_consent""#))
        .expect("the pyo3 signature line must exist");
    assert!(
        sig.contains("analyze = false"),
        "the fold's consent call must accept `analyze`. Without it an embedded agent can consent \
         to SEND traces and can never consent to BE SCORED, so capacity scoring is structurally \
         dead on every node that boots through the fold — which is every embedded agent.\n\
         got: {sig}"
    );
    // Match on the CALL's argument list, whitespace-insensitively — rustfmt
    // wraps this across lines the moment a third argument is added, and a gate
    // that a formatter can silently break is not a gate.
    let call = src
        .split_once("author_consent_embedded(")
        .map(|(_, rest)| rest.split_once(')').map(|(a, _)| a).unwrap_or(""))
        .unwrap_or("");
    let call_args: String = call.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        call_args.contains("analyze"),
        "accepting `analyze` is not enough — it must be THREADED to author_consent_embedded. A \
         parameter that is accepted and dropped is the worst shape available here: the wizard \
         passes True, the call returns Ok, and nothing was authored.\n\
         call args: {call_args}"
    );
}

/// Omitting the prefixes must mean "this build's production default", so a
/// caller with no policy of its own cannot restate — and thereby fork — ours.
#[test]
fn prefixes_are_optional_so_the_default_is_exercised_not_restated() {
    let src = lib_rs();
    let sig = src
        .lines()
        .find(|l| l.contains(r#"name = "author_federation_consent""#))
        .expect("the pyo3 signature line must exist");
    assert!(
        sig.contains("attestation_prefixes = None"),
        "attestation_prefixes must default to None (⇒ the production default). Required-arg \
         form forces every caller to name a set, and the harness named ['trace:','capacity:'] \
         for eight releases while production shipped ['capacity:'] and moved ZERO traces. A \
         fixture that supplies the value production defaults cannot prove the default.\n\
         got: {sig}"
    );
}

/// Peer selection must NOT be baked into the consent call.
#[test]
fn the_surface_does_not_decide_which_peers_to_consent_to() {
    let src = lib_rs();
    for banned in ["consent_to_canonicals", "consent_to_all_peers"] {
        assert!(
            !src.contains(banned),
            "`{banned}` bakes a peer-selection policy into the substrate. Who to consent to is \
             the agent's exhaustive consent form and it changes per deployment ('traces to \
             canonicals blessed by a trust root I trust', 'medical data to medical providers my \
             providers trust'). Enumerate + filter belongs to the caller; this crate authors one \
             grant to one named peer."
        );
    }
}

/// The docstring must not send an in-fold caller to HTTP. This is the exact
/// sentence that produced the 404.
#[test]
fn the_docstring_does_not_point_the_fold_at_a_route_the_fold_cannot_serve() {
    let src = lib_rs();
    let start = src
        .find("name = \"author_federation_consent\"")
        .expect("signature present");
    let doc_start = src[..start]
        .rfind("#[pyfunction]")
        .expect("attribute present");
    let doc = &src[doc_start..start];

    assert!(
        !doc.contains("exclusively the owner-gated POST"),
        "the doc claimed production consent is EXCLUSIVELY the owner-gated POST. That stopped \
         being true in 0.5.147 (author_consent_embedded, gated on the node being CLAIMED), and \
         a wizard believing it called HTTP inside the fold and got a 404."
    );
    assert!(
        doc.contains("start_and_hold") && doc.contains("404"),
        "the doc must state WHY HTTP cannot work in the fold — start_and_hold mounts no router, \
         so the owner-gated routes 404 by construction. Saying 'use this instead' without the \
         reason invites the next caller to try HTTP first and read the 404 as a transient."
    );
}

/// **Rule 2 must state its three costs, wherever it is read.**
///
/// Sending traces without consenting to be analyzed is ALLOWED — traces flow.
/// It is degraded, not refused, and the degradation is specific:
///
///   1. no reputation — every `capacity:*` claim about you is refused, so none
///      can ever exist;
///   2. no capability-gated streams or services — you will have none to present;
///   3. some peers may refuse to interact at all.
///
/// A warning that says only "consider enabling analyze" is the same failure as
/// the docstring that produced the 404: confident, and uninformative about the
/// branch the reader is actually in. The costs are what make the choice a
/// choice, so they are pinned rather than left to whoever next edits the string.
#[test]
fn declining_to_be_scored_states_what_it_costs() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/federation_delivery.rs"),
    )
    .expect("src/federation_delivery.rs must be readable");

    let start = src
        .find("WITHOUT the CC#46")
        .expect("the no-analyze WARN must exist — silence is how 240 peers got here");
    let warn: String = src[start..start + 1200]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for (cost, needle) in [
        ("(1) no reputation", "NO reputation"),
        (
            "(2) no capability-gated services",
            "third-party capability attestations",
        ),
        ("(3) peers may refuse", "refuse to interact"),
    ] {
        assert!(
            warn.contains(needle),
            "the no-analyze WARN must name cost {cost}. Declining to be scored is a legitimate \
             configuration, so the log has to explain what the operator gave up — not scold them \
             for a choice they are allowed to make.\nwarn: {warn}"
        );
    }
    assert!(
        warn.contains("ALLOWED"),
        "the WARN must say this is ALLOWED. It reads as a misconfiguration otherwise, and an \
         operator who deliberately declined scoring will treat the whole line as noise — \
         including the three costs they most need to read."
    );
}

/// **Rule 1 and rule 2 must both be on the public front page.**
///
/// `cirisai.github.io/CIRISServer` renders `main:/README.md`, so this IS the
/// page an operator reads before standing up a node. Both rules govern what they
/// get back from the mesh, and neither is discoverable from the code.
#[test]
fn the_readme_states_both_mesh_participation_rules() {
    let raw = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"))
        .expect("README.md must be readable");
    // Markdown hard-wraps prose, so a phrase that reads as one sentence is split
    // across lines in the source. Normalize before matching — a gate a text
    // reflow can break is not a gate (same lesson as rustfmt wrapping the call
    // above).
    let readme: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(
        readme.contains("no service access on the mesh and no agent services"),
        "rule 1 must be on the front page: a node that does not announce gets no service access \
         and no agent services, because the kill switch is only meaningful against a node it can \
         reach. An operator who learns this after deploying learns it as an outage."
    );
    assert!(
        readme.contains("kill switch"),
        "rule 1 without its REASON is an arbitrary-sounding restriction, and arbitrary-sounding \
         restrictions get worked around. Say why: an unreachable node cannot be halted."
    );
    assert!(
        readme.contains("TWO consents"),
        "rule 2 must be on the front page. Sending traces and being scored are different edges; \
         an operator who authors one and assumes the other gets a node that builds no reputation \
         and cannot use capability-gated services, with nothing in the UI saying so."
    );
}

/// **The wizard's copy ships from the wheel, and it must be complete.**
///
/// A wizard that composes its own explanation of the consent choice drifts from
/// the substrate the moment either changes — the exact failure that hid a dead
/// trace plane for eight releases (the harness restated the prefixes) and sent
/// an in-fold wizard to a 404 (a docstring restated the route). So the copy is
/// data, read from `consent_disclosure()`, and its load-bearing parts are pinned
/// here: an operator can only decline scoring *knowingly* if the three costs are
/// actually in front of them.
#[test]
fn the_consent_disclosure_states_both_rules_and_all_three_costs() {
    let json: serde_json::Value =
        serde_json::from_str(&ciris_server::peer::consent_disclosure_json())
            .expect("consent_disclosure must be valid JSON — a wizard parses it");

    let grants = json["grants"].as_array().expect("grants array");
    assert_eq!(grants.len(), 2, "there are exactly TWO consents; a disclosure naming one lets an operator grant it and assume the other");
    assert_eq!(
        grants[0]["required"], true,
        "the replication grant is required to send traces at all"
    );
    assert_eq!(
        grants[1]["required"], false,
        "the analyze grant is OPTIONAL — sending traces without it is allowed. Marking it \
         required misrepresents a legitimate choice as a misconfiguration."
    );
    assert_eq!(grants[1]["scope"], "analyze");
    assert!(
        json["independent"]["text"]
            .as_str()
            .is_some_and(|s| s.contains("does not")),
        "the disclosure must say granting one does NOT grant the other. The natural reading of \
         'share my traces' is that scoring rides along, and it does not."
    );

    let declining = &json["declining_analyze"];
    assert_eq!(
        declining["allowed"], true,
        "declining must be presented as ALLOWED. Framed as an error, an operator who meant it \
         dismisses the whole disclosure — including the costs they most need."
    );
    let costs = declining["costs"].as_array().expect("costs array");
    assert_eq!(
        costs.len(),
        3,
        "all three costs, or the choice is not informed"
    );
    let joined = costs
        .iter()
        .filter_map(|c| c["text"].as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    for needle in [
        "NO reputation",
        "third-party capability attestations",
        "refuse to interact",
    ] {
        assert!(
            joined.contains(needle),
            "missing cost {needle:?} in: {joined}"
        );
    }

    let announce = json["announce_requirement"]["text"]
        .as_str()
        .expect("announce_requirement");
    assert!(
        announce.contains("no service access") && announce.contains("kill switch"),
        "rule 1 must ride along with its reason. A wizard that omits it ships a node whose \
         operator learns the announce requirement as an outage.\ngot: {announce}"
    );
}

/// **The screen shape, and location as the ONE H3 representation.**
///
/// The consent screen is a single primary action — "Consent to CIRIS Mesh
/// Participation" — with the detail expandable beneath it. An operator who
/// expands nothing still gave a real consent, so the button has to name the
/// whole bundle rather than its first item.
///
/// Location sits on that screen but is a different KIND of thing: neither a
/// consent object nor an agent-tier data field, but a signed `location_proof`
/// carrying an H3 cell on the envelope (CEG 0.8 §0.8). That is the SAME
/// representation everywhere — server, agent, every producer — and a producer
/// shipping raw coordinates instead is non-conformant rather than merely
/// different.
#[test]
fn the_screen_shape_and_the_h3_location_field() {
    let json: serde_json::Value =
        serde_json::from_str(&ciris_server::peer::consent_disclosure_json()).unwrap();

    assert_eq!(
        json["primary_action"]["id"], "consent.mesh_participation.action",
        "one button naming the whole bundle — not the first item in it"
    );
    assert_eq!(json["details_expandable"], true);

    let loc = &json["location"];
    assert_eq!(
        loc["kind"], "envelope_field",
        "location rides the ENVELOPE as a location_proof. Modelled as a consent object it \
         acquires a withdrawal lifecycle it does not have; modelled as an agent-tier field it \
         becomes a second representation, and there is exactly one."
    );
    assert_eq!(loc["cell_format"], "h3");
    assert_eq!(
        loc["max_resolution"],
        ciris_persist::federation::location::MAX_LOCATION_PROOF_RESOLUTION,
        "the rough-only bound must be READ from persist, never restated here. §0.8.1 is enforced \
         at admission — validate_location_cell refuses anything finer, and resolution-redundancy \
         stops a producer asserting a coarse resolution while shipping a fine cell. So 'rough \
         region only' is a property of the wire format, not a promise a UI makes on a client's \
         behalf. A hand-copied number would outlive a substrate change silently."
    );

    let purpose = loc["purpose"]["text"].as_str().expect("location purpose");
    assert!(
        purpose.contains("Regional pattern reporting"),
        "lead with what location is FOR — reporting patterns across regions. Presented first as \
         a restriction mechanism it reads as a pure cost, and an operator declines it.\ngot: {purpose}"
    );
    assert!(
        purpose.contains("OPTIONAL visibility gate"),
        "...and do not overclaim in the other direction. A geographic community MAY restrict \
         items destined for it to members whose region falls inside it. 'Location never affects \
         visibility' is the simpler sentence and it is false.\ngot: {purpose}"
    );

    let costs = loc["declining"]["costs"].as_array().expect("costs");
    assert_eq!(
        costs.len(),
        2,
        "declining location costs regional reporting AND regional community membership"
    );
}
