//! **What `POST /v1/files` answers must be what `GET /v1/files/{id}` accepts**
//! (CIRISServer#622).
//!
//! # The two rows
//!
//! A crossing that WIDENS is two rows: the authored one (`self`, local tier —
//! the producer's own copy) and the `supersedes` row placed at the wider
//! audience, which carries a **new id**. Edge states it on `Shared::Placed`:
//! "After a widening this is the NEW `supersedes` row's id, not the one passed
//! in."
//!
//! So `published.row.attestation_id` is the id of the row that did NOT cross.
//! Answering with it hands a client an identifier for something only this node
//! has.
//!
//! # Measured
//!
//! On the chat ladder, `POST /v1/files {cohort:"community"}` answered
//! `file-f9d37acb…` while the row at `cohort_scope=community` was `e0d4dcdc-…`.
//! Reading back by the answered id was `404 drive.not_in_room` — on the
//! recipient's node *and on the author's own*, because `file-f9d37acb…` is only
//! the `self`-scoped copy. A client that stored what the write returned could
//! never open its own file.
//!
//! **Why every self test stayed green over it:** a `self` write does not widen,
//! so the authored id IS the placed id. The bug needed a cohort that widens,
//! and the self-file ladder — the one built first — could not reach it. That is
//! the whole argument for exercising more than one cohort.

/// Source with line endings normalised — CRLF checkouts break these needles.
fn read_src(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("\r\n", "\n")
}

/// No write door answers with the AUTHORED row's id.
#[test]
fn no_write_door_answers_with_the_authored_row_id() {
    let src = read_src("src/drive.rs");
    // `readable_id` is the ONE place allowed to name the authored row — it is
    // the fallback for a crossing that placed nothing. Scan everything else.
    let helper_start = src.find("fn readable_id(").expect("readable_id must exist");
    let helper_end = src[helper_start..]
        .find("\n}\n")
        .map_or(src.len(), |n| helper_start + n);
    let offenders: Vec<usize> = src
        .match_indices("published.row.attestation_id")
        .filter(|(i, _)| !(*i >= helper_start && *i < helper_end))
        .filter(|(i, _)| {
            let line_start = src[..*i].rfind('\n').map_or(0, |n| n + 1);
            let line = src[line_start..*i].trim_start();
            // Prose about the bug is not the bug; a tracing field naming the
            // producer's own copy is legitimate and useful. Only CODE that
            // hands the value back is a finding.
            !line.starts_with("///")
                && !line.starts_with("//")
                && !line.contains("attestation_id = %")
        })
        .map(|(i, _)| src[..i].matches('\n').count() + 1)
        .collect();
    assert!(
        offenders.is_empty(),
        "these lines answer a caller with the AUTHORED row's id, which after a widening \
         names a row that never crossed — the client cannot read its own file back \
         (lines {offenders:?}). Use `readable_id(&published)`, which takes the id off \
         `Shared::Placed`/`AlreadyThere`."
    );
}

/// And the helper reads the id off the CROSSING, not off the authored row.
#[test]
fn readable_id_takes_the_id_from_the_crossing() {
    let src = read_src("src/drive.rs");
    let start = src
        .find("fn readable_id(")
        .expect("readable_id is the one place the answered id is chosen");
    let body = &src[start..src.len().min(start + 1400)];
    for needle in ["Shared::Placed", "AlreadyThere", "AwaitingActor"] {
        assert!(
            body.contains(needle),
            "readable_id must handle {needle} explicitly — a crossing has three outcomes \
             and only two of them placed anything"
        );
    }
}
