//! **The `redirect_uri` we emit is the PUBLIC url, which this node cannot
//! derive** (CIRISServer#421).
//!
//! The public URL and the served path are DIFFERENT STRINGS, and that is by
//! design. nginx routes the public three-segment URL and strips the agent-id
//! before forwarding, so one Google client (datum's) serves every agent: the
//! agent-id exists for proxy routing and console registration and never reaches
//! the app. The node therefore correctly serves — and correctly receives — two
//! segments.
//!
//! So the defect is one-directional. The node derived `redirect_uri` from the
//! path it serves and advertised that INTERNAL path publicly. nginx will not
//! route it (its location regex requires the agent segment) and no console
//! entry carries it.
//!
//! It took TWO deltas together, which is why neither alone explained it: the
//! derived path lacked the agent-id, AND the base fell back to loopback because
//! the config PUT that sets `auth.oauth_callback_base_url` 403s on an unclaimed
//! node. The deployment never changed — `OAUTH_CALLBACK_BASE_URL`,
//! `CIRIS_AGENT_ID` and the volume mount are byte-identical across
//! `docker-compose.yml`, `.pre-cutover` and `.pre-migration`. Only our code did.
//!
//! Hence: the value must be REGISTERED by the agent, from its own environment,
//! and sent back verbatim. There is nothing here to derive.
//!
//! # What these do NOT assert
//!
//! Earlier drafts of this file claimed the missing route was the bug and that
//! restoring it fixed hosted login. That was wrong, and wrong in the direction
//! that matters: someone acting on it would make the emitted URI match the
//! node's own routes and re-break every hosted login. The three-segment routes
//! are defence-in-depth for a direct-to-node request only.

/// Path shapes this node answers on, as declared in `oauth_router`.
const SERVED: &[&str] = &[
    "/v1/auth/oauth/{provider}/login",
    "/v1/auth/oauth/{provider}/callback",
    "/v1/auth/oauth/{agent_id}/{provider}/login",
    "/v1/auth/oauth/{agent_id}/{provider}/callback",
];

fn router_src() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/auth/oauth.rs"),
    )
    .expect("src/auth/oauth.rs unreadable — this gate cannot run")
}

/// **Defence in depth, and labelled as such.**
///
/// The hosted path never reaches this node — nginx strips the agent-id — so
/// these routes are for a direct-to-node request that skips the proxy. They are
/// NOT what fixes hosted login; the emitted URI is. This asserts they exist and,
/// more importantly, that the file still says why they are not the fix.
#[test]
fn the_agent_id_shape_is_routed_as_defence_in_depth() {
    let src = router_src();
    for want in [
        "/v1/auth/oauth/{agent_id}/{provider}/callback",
        "/v1/auth/oauth/{agent_id}/{provider}/login",
    ] {
        assert!(src.contains(want), "no route for `{want}`");
    }
    assert!(
        src.contains("DEFENCE IN DEPTH ONLY"),
        "the three-segment routes lost the note explaining that nginx strips the \
         agent-id and that these are NOT the fix for #421. Without it the next reader \
         concludes the emitted redirect_uri should be made to match these routes, which \
         re-breaks every hosted login — the exact wrong turn this file exists to prevent."
    );
}

/// **The two-segment shape stays** — it is what nginx forwards AND what desktop
/// registers on loopback.
///
/// This is the load-bearing route in every deployment. Removing it to "clean
/// up" after adding the three-segment pair would break both flows at once.
#[test]
fn the_loopback_callback_shape_is_still_routed() {
    let src = router_src();
    assert!(
        src.contains("/v1/auth/oauth/{provider}/callback"),
        "the two-segment callback route is gone. The bundled desktop client registers a \
         LOOPBACK redirect of exactly that shape, so dropping it trades a hosted outage \
         for a desktop one."
    );
}

/// **Both ends of a flow resolve the URI through ONE function.**
///
/// The authorize redirect and the code exchange must send byte-identical
/// values. They were two independent `oauth_callback_url(...)` calls that agreed
/// only because they were written the same day; a registered URL reaching one
/// and not the other fails at the exchange, after the user has already consented.
#[test]
fn both_flow_ends_resolve_the_uri_the_same_way() {
    let src = router_src();
    let resolver_calls = src.matches("redirect_uri_for(").count();
    assert!(
        resolver_calls >= 3,
        "expected the resolver's definition plus BOTH flow call sites (authorize + \
         exchange); found {resolver_calls} mention(s). If one end derives while the other \
         uses the registered URL, the provider rejects the exchange after consent — the \
         worst place to fail, because the user has already done their part."
    );
}

/// **A registered URL is used verbatim; absent, the derived shape is unchanged.**
#[test]
fn registered_wins_and_absent_falls_back() {
    let derived =
        ciris_server::auth::oauth::oauth_callback_url_for_test("http://127.0.0.1:4243", "google");
    assert_eq!(
        derived, "http://127.0.0.1:4243/v1/auth/oauth/google/callback",
        "the derived (desktop/loopback) shape moved — that is the one thing that was \
         working, and the flow it serves registers this exact string"
    );

    // The hosted registration must come back BYTE-IDENTICAL. Any normalisation
    // — a trailing slash, a re-encoded segment — is a different string to the
    // provider and fails the same way the missing segment did.
    let registered = "https://agents.ciris.ai/v1/auth/oauth/datum/google/callback";
    assert_eq!(
        ciris_server::auth::oauth::redirect_uri_for_test(
            Some(registered),
            "http://127.0.0.1:4243",
            "google"
        ),
        registered,
        "a registered callback_url was not sent back verbatim. The deployment is the only \
         authority on this string — it is whatever was typed into the provider's console — \
         so anything we do to it other than pass it through is a guess, and the guess is \
         what CIRISServer#421 was."
    );

    // And the derived shape must still win when nothing is registered, so the
    // desktop flow is untouched.
    assert_eq!(
        ciris_server::auth::oauth::redirect_uri_for_test(None, "http://127.0.0.1:4243", "google"),
        derived,
        "with no registered URL the derived loopback shape must be unchanged"
    );

    let _ = SERVED;
}
