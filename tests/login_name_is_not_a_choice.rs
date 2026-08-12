//! **A login name that resolves to two certs must REFUSE, not pick**
//! (CIRISAgent#1029).
//!
//! # The report
//!
//! CIRISAgent routed `/v1/auth/*` at the node and their QA suite could not get
//! past login. The node said `password mismatch — the cert WAS resolved`, and the
//! *same* username and password were 3/3 green against the Python moments before.
//! They had already ruled out the obvious: PBKDF2 parameters match on both sides
//! (salt 32 / key 32 / 100k / `b64(salt||key)`), and the hash is written where the
//! node reads it.
//!
//! Their lead was right, and the code said so in a comment:
//!
//! ```text
//! // Names are not guaranteed unique; the most-recent active match wins
//! ```
//!
//! Their setup writes `system_admin_password` onto the admin WA and
//! `admin_password` onto the user WA. When both certs carry the same human `name`,
//! the two implementations resolve DIFFERENT certs — and the node then compares a
//! correct password against the wrong cert's hash, forever.
//!
//! # Why "most-recent wins" is the wrong answer, not a rough one
//!
//! Picking is a silent authentication decision. On a successful password it signs
//! the caller in as whichever cert the node happened to order first, with that
//! cert's role and rights. That is the same hazard as
//! [`StoreError::AmbiguousOauthIdentity`], which already refuses — this is the
//! identifier humans actually type, and it was the one still choosing.
//!
//! It is also the same reasoning that keeps name matching EXACT rather than
//! accepting a first name: on this path, ambiguity means signing in as the wrong
//! person.
//!
//! # The shape, not the string
//!
//! Both resolvers now share ONE scan (`certs_named`) and one decision
//! (`one_named`). Two copies were how `resolve_login` and
//! `resolve_login_detailed` could come to disagree about who `jeff` is — and the
//! detailed one is what login uses while the plain one is what everything else
//! uses, so a disagreement there is invisible until someone's rights are wrong.

use std::path::Path;

fn src(rel: &str) -> String {
    // Normalized: a CRLF checkout otherwise breaks every `\n`-bearing assertion,
    // which has cost this repo three Windows-only CI failures.
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
        .replace("\r\n", "\n")
}

/// Strip `//` comments — a comment naming the behaviour is not the behaviour.
fn code_only(s: &str) -> String {
    s.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The refusal must exist as a distinct error, not be folded into "not found".
#[test]
fn an_ambiguous_name_is_its_own_error() {
    let code = code_only(&src("src/auth/store.rs"));
    assert!(
        code.contains("AmbiguousLoginName"),
        "a name resolving to several active certs needs its OWN error. Folding it into `None` \
         reports 'no such user' for an account that exists twice; folding it into the OAuth \
         variant loses which identifier collided."
    );
    assert!(
        code.contains("holders: Vec<String>"),
        "the error must carry the colliding wa_ids — this is the one login failure an operator \
         can fix, and only if told what collided"
    );
}

/// **The regression that matters**: neither resolver may silently take the first
/// match. `.find(` over the role scan is exactly the shape that shipped.
#[test]
fn neither_resolver_picks_the_first_match() {
    let code = code_only(&src("src/auth/store.rs"));
    let start = code.find("async fn certs_named").expect("the shared scan");
    let end = code.find("/// Point lookup by").unwrap_or(code.len());
    let resolvers = &code[start..end];
    assert!(
        !resolvers.contains(".find(|c| c.name == ident)"),
        "a resolver is choosing between same-named certs again. Return ALL matches and refuse on \
         more than one — picking is a silent authentication decision:\n{resolvers}"
    );
    assert!(
        resolvers
            .matches("one_named(ident, certs_named(engine, ident).await?)")
            .count()
            >= 2,
        "BOTH resolvers must go through the shared scan + shared decision. Two copies are how \
         `resolve_login` and `resolve_login_detailed` come to disagree about who a name means — \
         and login uses one while everything else uses the other."
    );
}

/// The refusal must NOT surface as `401 invalid credentials`. That is what made
/// the agent's report so expensive: a correct password reported as wrong, with
/// nothing pointing at the actual cause.
#[test]
fn the_refusal_does_not_masquerade_as_a_bad_password() {
    let code = code_only(&src("src/auth/session.rs"));
    let arm = code
        .find("StoreError::AmbiguousLoginName")
        .map(|i| &code[i..(i + 600).min(code.len())])
        .expect("the login handler must match the ambiguity arm explicitly");
    assert!(
        arm.contains("StatusCode::CONFLICT"),
        "an ambiguous name is a 409 — the store is healthy and the credential may be perfectly \
         valid. 401 says 'wrong password' about a password that is right, and 503 says the store \
         is down when it is not:\n{arm}"
    );
}

/// The miss report must stay meaningful. `scanned` separates "this node reads a
/// different database" (0) from "the certs are here and none is named that" (>0);
/// building it before the name scan would count matches as misses.
#[test]
fn the_miss_report_is_built_only_after_the_name_scan_fails() {
    let code = code_only(&src("src/auth/store.rs"));
    let i = code
        .find("pub async fn resolve_login_detailed")
        .expect("the detailed resolver");
    let body = &code[i..code[i..].find("\n}").map(|j| i + j).unwrap_or(code.len())];
    let scan_at = body.find("one_named(ident,").expect("the name scan");
    let miss_at = body.find("LoginMiss::default()").expect("the miss report");
    assert!(
        scan_at < miss_at,
        "the miss report must be built AFTER the name scan comes back empty — otherwise a \
         resolved cert is also counted as a scanned miss, and `scanned` stops meaning what the \
         operator is told it means"
    );
}
