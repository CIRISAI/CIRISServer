//! The fabric auth subsystem — **CIRISServer as the single auth authority**
//! (CIRISServer#9).
//!
//! Consolidates what lived in the agent (WiseAuthority certs, OAuth→WA→JWT, the
//! agent's own user store + role taxonomy) onto the CEG substrate: one
//! federation identity, one hybrid request contract, one role model, self-at-
//! login as the login ceremony, and the owner-binding gate. "Infra must not have
//! agency / the human acts through the node" ⇒ the auth **authority** is the
//! fabric; the agent becomes a consumer/delegate (that migration is a later
//! slice). Bolting auth onto the agent while the fabric also signs would create
//! the two-authority conflict #9 exists to remove.
//!
//! ## This (core-first) pass
//! - [`verify`] — the one `x-ciris-*` hybrid request verifier (user-direct **or**
//!   agent-delegate — the §9 "as the user" / "on behalf of" split).
//! - [`self_login`] — the self-at-login ceremony (§8.1.12.7): co-admit the
//!   user's app + agent occurrences; the prerequisite for user-signed
//!   consent/erasure.
//! - [`roles`] — the CEG role-set `{user,node,agent,steward,witness,accord_holder}`
//!   + the infra/agency reserved-scope split.
//! - [`gate`] — the owner-binding gate (user-before-non-canonical-groups).
//! - [`session`] — the login session issuer (scaffold).
//!
//! ## Next slices (NOT this pass)
//! - Fold the registry user/org store onto CEG communities (rides the registry
//!   fold, CIRISServer#2).
//! - Migrate the agent to consumer/delegate (drop its WA / JWT / own identity;
//!   it acts under `delegates_to(user → agent)` — cross-repo).

pub mod api_keys;
pub mod attestation;
/// ROOT-user bootstrap + first-time-setup (CIRISServer#19): the baked
/// trust-anchor seed load, admin-eligible auto-mint, and the first-run
/// `POST /v1/setup/root` claim — the founder-becomes-`SYSTEM_ADMIN` flow that
/// unblocks owner-gated `POST /v1/federation/peering`.
pub mod bootstrap;
pub mod consent;
pub mod device_auth;
/// Node-side device-authorization grant (RFC 8628 shape): an external client/agent
/// is authorized to act on the OWNER's behalf via the node API. The owner approves
/// a human-typeable `user_code` from a hardware-backed (YubiKey/TPM) fed-ID
/// session; the issued DELEGATED token carries the owner's AUTHORITY and the
/// client's ATTRIBUTION (`SessionCaller.actor`). The mirror-direction of
/// [`device_auth`] (which is THIS node as a client of a Portal's grant).
pub mod device_grant;
pub mod erasure;
pub mod gate;
pub mod oauth;
/// Node ownership = the **responsible-party** model (CC 4.4.3.5 + CC 3.2 +
/// CC 1.13.5): a fabric node has NO agency, so ownership is a `user`-role
/// responsible party bound by an `infra:*`-only `delegates_to` — NOT the
/// agent's joint-agency partnership. Carries the infra/agency scope-split
/// verifier ([`ownership::scopes_are_infra_only`]), the owner-binding emitter,
/// and the [`ownership::is_owner_bound`] reader.
pub mod ownership;
pub mod roles;
pub mod self_login;
pub mod session;
pub mod store;
pub mod verify;
