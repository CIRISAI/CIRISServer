//! **The node states where it wrote the claim PIN; the client stops guessing**
//! (CIRISServer#395).
//!
//! The one-time claim PIN is written `0600` to `<home>/claim_pin` and served by no
//! route. The co-located wizard proves operator presence by READING that file —
//! and that is a real check, stronger than the loopback gate around it: loopback
//! admits any local process of any user, while a 0600 read admits only the uid
//! that started the node.
//!
//! The mechanism was built and correct. What was unreliable was the ADDRESS. The
//! client derived the node's home from its OWN environment:
//!
//! ```text
//! CIRIS_HOME, else $HOME/ciris, else user.home/ciris
//! ```
//!
//! Every one of those describes the app's process, not the node's. Whenever the
//! two disagreed — a launcher passing `--home`, a container, systemd, sudo, a
//! sandboxed run — the app read a path the node never wrote, and first-run claim
//! failed `401 invalid one-time claim PIN` with the file readable a directory
//! away. Intermittent by construction: it worked exactly when the two environments
//! happened to agree.
//!
//! # The fix is to remove the inference, not to weaken the check
//!
//! The node is the only party that KNOWS its home — it was told at startup. So
//! `GET /v1/setup/status` now carries `claim_pin_file`: the PATH, never the PIN.
//!
//! The first thing I tried instead was to have the server substitute its
//! in-process PIN whenever the target was itself. That would have "worked", and it
//! was wrong: it replaces a same-uid proof with a loopback proof and silently
//! lowers the bar for every self-claim. Recorded here because the failing symptom
//! (`401` on a claim that should be automatic) invites exactly that fix, and the
//! next person to see it deserves to know it was considered and rejected.

use std::path::Path;

fn src() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/auth/bootstrap.rs"))
        .expect("read src/auth/bootstrap.rs")
}

/// Strip `//` line comments before asserting about code. A comment that names the
/// symbol is not the symbol — this repo has had three gates pass on their own
/// prose.
fn code_only(s: &str) -> String {
    s.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The path is published on the setup-status read.
#[test]
fn setup_status_declares_the_pin_file_path() {
    let code = code_only(&src());
    assert!(
        code.contains("claim_pin_file: Option<String>"),
        "GET /v1/setup/status must carry the PIN FILE PATH so the wizard reads the file the node \
         actually wrote, instead of inferring a location from the APP's environment"
    );
    assert!(
        code.contains("st.claim_pin_file"),
        "the field must be sourced from the node's OWN configured path — deriving it here from \
         anything else would reintroduce the inference this removes"
    );
}

/// **The PIN itself must never be served.** The whole security model is that the
/// secret lives only on disk under 0600 and in-process; publishing the path is
/// safe precisely because the file's mode is the gate. Publishing the value would
/// destroy it.
#[test]
fn the_pin_value_is_never_in_the_status_response() {
    let raw = src();
    let start = raw
        .find("async fn setup_status(")
        .expect("the setup_status handler");
    let end = raw[start..]
        .find("\n}\n")
        .map(|i| start + i)
        .unwrap_or(raw.len());
    let handler = code_only(&raw[start..end]);

    // The handler may LOCK the PIN to ask whether one is armed, but must never move
    // the value into the response. Any clone/deref of the inner String is the
    // shape that would leak it.
    assert!(
        !handler.contains("claim_pin: Some") && !handler.contains("pin.clone()"),
        "the PIN VALUE must never reach the setup-status response — it is 'console-only, NEVER \
         over HTTP', and the 0600 file is what proves operator presence. Serving it would make \
         the read prove nothing.\n\nhandler:\n{handler}"
    );
    assert!(
        handler.contains("is_some()"),
        "the path should be published only while a PIN is actually armed — a claimed node \
         pointing at a consumed file is the 'look here and find nothing' shape"
    );
}

/// The field must be omitted, not `null`-stuffed, when no PIN is armed — and the
/// client treats absent as "fall back to the guess", which is correct for an old
/// server too.
#[test]
fn the_path_is_omitted_rather_than_empty_when_no_pin_is_armed() {
    let raw = src();
    let idx = raw
        .find("    claim_pin_file: Option<String>,")
        .expect("the field");
    assert!(
        raw[..idx].ends_with("#[serde(skip_serializing_if = \"Option::is_none\")]\n"),
        "omit the field when there is no armed PIN; a present-but-null path reads as 'the node \
         says there is no file' rather than 'this node cannot tell you', and the client's \
         fallback distinguishes those"
    );
}
