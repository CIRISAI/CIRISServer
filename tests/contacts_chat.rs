//! **Contacts + user chat, end to end over the real router.**
//!
//! Drives [`ciris_server::contacts_chat::router`] on a bound TCP listener
//! against an in-memory substrate, so the full HTTP + owner-auth stack runs and
//! nothing under test is stubbed. Four questions, in the order the flow asks
//! them:
//!
//! 1. **Add a contact by fedID** writes the `consent:replication:v1` grant that
//!    IS the contact relationship, resolves the contact's identity occurrences,
//!    and is idempotent. The contact then appears in `GET /v1/contacts` on the
//!    peer card shape the client already renders.
//! 2. **Chat creation converges.** The community id is DERIVED from the pair, so
//!    the test recomputes it independently — in both argument orders — and
//!    demands the route's answer match. A room both ends can only reach by
//!    agreeing first is not a room.
//! 3. **Send + list round-trips**, and the listed message carries its CEG
//!    identity: `attestation_id`, `attesting_key_id`, `cohort_scope`, and the
//!    folded `status`. The client reuses its attestation hamburger on each
//!    message, so a shape that hid those would be a second, weaker object model.
//! 4. **A non-member cannot read the community's messages** — and this is the
//!    one that matters. The community in that test holds a REAL message; the
//!    caller is the node's own OWNER; the refusal comes from persist's own §4.3
//!    predicate. Owning the box is not membership in the cohort, and if that
//!    arm ever goes quiet the `community` tier means nothing.
//!
//! Test 4 is paired with a control (`the_owner_reads_their_own_community`) for
//! the reason the whole file exists: a refusal test that passes because the
//! fixture never worked proves nothing.
//!
//! # Two things the fixture must genuinely BE, not merely register
//!
//! A send now needs both halves of a real conversation, so neither can be
//! faked with a directory row:
//!
//! * **the owner holds their key** — the message is signed by the PERSON, and
//!   the route opens that key off disk ([`OwnerIdentity`]);
//! * **the contact answers the handshake** — the body is sealed under the
//!   room's MLS record secret, so this single-node fixture plays the far side
//!   ([`open_chat`], [`contact_room_key`]).
//!
//! Both are the same lesson as the control above, one rung down: a fixture that
//! only looks like the other party keys no room and signs no words.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{
    algorithm, attestation_type, cohort_scope, identity_type, IdentityOccurrence, KeyRecord,
    LocalAttestationInput, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_persist::federation::{Audience, CrossingBasis};
use ciris_server::auth::session::DelegationConstraints;
use ciris_server::auth::store;
use ciris_server::contacts_chat::{self, pair_community_key_id};
use ciris_server::identity::UserIdentityBackend;

const NODE_KEY_ID: &str = "ciris-server";

/// The contact the owner chats with.
const CONTACT_KEY_ID: &str = "bob-v1";
/// The contact's phone — proves the occurrence resolution is real.
const CONTACT_OCCURRENCE_KEY_ID: &str = "bob-v1-phone";
/// Two strangers whose community the owner is deliberately NOT in.
const STRANGER_A_KEY_ID: &str = "carol-v1";
const STRANGER_B_KEY_ID: &str = "dave-v1";

/// Stranger A as an IDENTITY that can sign, under the DERIVED id.
///
/// Placing a row into a community is a MEMBERSHIP claim (persist v39.0.0
/// refuses `WriteScopeRefused(NoCommunityMembership)` otherwise), so the row
/// must be attested by a member — and this node is deliberately NOT one in the
/// strangers' room. The member therefore has to sign it in, and `custody_for`
/// accepts a signer only when `derived_key_id() == attesting_key_id`, so the
/// membership, the attestation and the registration all use the derived id.
/// Same seeds as `seed_user_key` registers, so this is the same identity.
fn stranger_a_identity() -> (LocalSigner, String) {
    identity_for(STRANGER_A_KEY_ID, 0xC0, 0xC1)
}

/// A hybrid signer for `alias`, and the DERIVED id its rows must be attested and
/// registered under. Same seeds the `seed_*_key` helpers register, so the signer
/// and the directory row are one identity.
fn identity_for(alias: &str, ed_seed: u8, pqc_seed: u8) -> (LocalSigner, String) {
    let signer = LocalSigner::from_parts(
        SigningKey::from_bytes(&[ed_seed; 32]),
        alias.to_string(),
        Some(Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[pqc_seed; 32], format!("{alias}-pqc"))
                .expect("ml-dsa seed"),
        ) as Arc<dyn ciris_keyring::PqcSigner>),
        Some(format!("{alias}-pqc")),
    );
    let key_id = signer.derived_key_id();
    (signer, key_id)
}

// ─── Fixture ────────────────────────────────────────────────────────────────

/// This node: an in-memory substrate keyed by a HYBRID node-identity signer, so
/// `sign_hybrid` (the community self-signature + the promote reseal) works.
async fn node() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xA1; 32]),
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// The node's #247 DERIVED federation key_id — what `self_identity::resolve`
/// returns and what the consent grants are authored under.
async fn node_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id")
}

/// Register this node's own steward key through the canonical admission gate
/// (the `put_attestation` attesting-key FK precondition).
async fn register_self(engine: &Engine) {
    let key_id = node_key_id(engine).await;
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::STEWARD,
        serde_json::Value::Null,
    )
    .await
    .expect("register node steward key via admission gate");
}

/// Seed a `user`-role key straight into the directory. The routes under test
/// require the row to EXIST; key-admission coverage lives in
/// `tests/federation_admin.rs`.
/// Register a user key under the id it will be ATTESTED under. `seed_user_key`
/// spells the alias; `seed_user_key_at` spells a derived id for the same seeds
/// — the same identity, registered where `custody_for` will look for it.
async fn seed_user_key_at(engine: &Engine, key_id: &str, ed_seed: u8, pqc_seed: u8) {
    seed_user_key(engine, key_id, ed_seed, pqc_seed).await;
}

async fn seed_user_key(engine: &Engine, key_id: &str, ed_seed: u8, pqc_seed: u8) {
    let ed = SigningKey::from_bytes(&[ed_seed; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[pqc_seed; 32], format!("{key_id}-pqc"))
        .expect("ML-DSA-65 seed");
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize registration");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode(ed.verifying_key().to_bytes()),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(mldsa.public_key().await.expect("ml-dsa pk"))),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .unwrap_or_else(|e| panic!("seed user key {key_id}: {e}"));
}

/// One `CIRIS_HOME` for the whole test binary. [`OwnerIdentity::mint`] seals the
/// owner's ML-DSA-65 half into `ciris_verify_core::ceg_outbox::keys_dir()`,
/// which hangs off this env var — left unset, every test in this file would
/// write into the developer's real `~/ciris`. Set ONCE, because tests run in
/// parallel; what keeps two owners off the same seal file is the per-test
/// ALIAS, not this directory.
fn ciris_home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ciris-chat-home-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create CIRIS_HOME");
        std::env::set_var("CIRIS_HOME", &dir);
        dir
    })
    .clone()
}

/// **The owner's key, actually held.**
///
/// A chat message is signed by the PERSON, so `send_message` opens the owner's
/// fed-ID through `owner_signer_capsule::acquire` — which reads it off disk. A
/// federation-directory row with no custody behind it answers `NoFedIdentity`,
/// and every send 403s `chat.author_signer_unavailable`. The owner here is
/// therefore MINTED the way `POST /v1/self/identity` mints one: a real Ed25519
/// half under `alias` in `seed_dir`, a real ML-DSA-65 half sealed under the same
/// alias, and a registered id that is the #247 DERIVED `<alias>-<fp>` form.
///
/// That derivation is why the owner's key id is a runtime value in this file
/// rather than the constant it used to be: it embeds the fingerprint of a key
/// that did not exist until this test started.
struct OwnerIdentity {
    /// The keystore ALIAS — the storage key for BOTH halves, and what
    /// `resolve_user_signers` re-opens by.
    alias: String,
    /// The #247 DERIVED federation key_id: what the owner-binding names, what
    /// `require_owner_bound` hands the routes, and what every "this is the
    /// owner" assertion in this file spells.
    key_id: String,
    /// The seed directory — the SAME `PathBuf` [`serve`] hands `router`. The
    /// capsule resolves the signer out of the router's copy, so a fixture that
    /// minted anywhere else would mint a key the route cannot find.
    seed_dir: PathBuf,
    pubkey_ed25519_base64: String,
    pubkey_ml_dsa_65_base64: String,
}

impl OwnerIdentity {
    /// Mint one under an alias unique to this test.
    ///
    /// UNIQUE is load-bearing twice: the ML-DSA seal is keyed by alias inside a
    /// PROCESS-GLOBAL keyring directory, and `active_user_alias` is one pointer
    /// file per seed dir. Two tests sharing either would race — and tests here
    /// run in parallel, `concurrent_chat_creation_is_an_idempotent_success`
    /// building twelve fixtures of its own.
    ///
    /// The `alice-` prefix is not decoration: `PairRole::of` gives the
    /// lexicographically SMALLER fed-ID the creator's role, and [`open_chat`]
    /// keys the room by publishing the joiner's KeyPackage. Sorting the owner
    /// before [`CONTACT_KEY_ID`] is what makes the owner the creator; the
    /// assertion in `open_chat` is where that is stated out loud.
    async fn mint() -> Self {
        static NTH: AtomicU32 = AtomicU32::new(0);
        let alias = format!(
            "alice-owner-{}-{}",
            std::process::id(),
            NTH.fetch_add(1, Ordering::Relaxed)
        );
        let seed_dir = ciris_home().join(&alias);
        std::fs::create_dir_all(&seed_dir).expect("owner seed dir");
        let minted = ciris_server::identity::mint_user_identity(
            UserIdentityBackend::Software,
            &alias,
            Some("Chat Owner"),
            seed_dir.clone(),
            ciris_server::identity::ActiveAlias::Adopt,
        )
        .await
        .expect("mint the owner's fed-ID");
        assert!(
            minted.key_id.starts_with(&format!("{alias}-")),
            "expected a derived `{alias}-<fp>` key_id, got {}",
            minted.key_id
        );
        // THE FIXTURE NO LONGER WRITES THESE. It used to hand-write the custody
        // marker and the `active_user_alias` pointer beside the seed, because
        // only `POST /v1/self/identity` wrote them — so every mint reached any
        // other way produced an identity nothing could re-open, and this fixture
        // papered over it. `mint_user_identity` writes both now; asserting on
        // them here is what keeps that true.
        assert!(
            seed_dir.join(format!("{alias}.backend")).exists(),
            "the mint must record the custody backend beside the seed — without it \
             the re-open can pick a different backend than the one that minted"
        );
        assert_eq!(
            ciris_server::active_user_alias(&seed_dir, &minted.key_id),
            alias,
            "the mint must record the active_user_alias pointer. The capsule is \
             handed the owner-binding's DERIVED key_id, so without the pointer the \
             resolver looks for `<derived>.ed25519.seed`, finds `<alias>.ed25519.seed` \
             instead, and the node refuses to sign as its own owner"
        );
        Self {
            alias,
            key_id: minted.key_id,
            seed_dir,
            pubkey_ed25519_base64: minted.pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64: minted.pubkey_ml_dsa_65_base64,
        }
    }

    /// The owner's own signer, re-opened from the SAME custody the route reads.
    /// A binding or delegation this signs therefore verifies against the
    /// registered pubkeys — the fixture cannot sign with material the server
    /// does not hold.
    async fn signer(&self) -> LocalSigner {
        ciris_server::identity::hardware_user_signers(
            UserIdentityBackend::Software,
            &self.alias,
            self.seed_dir.clone(),
        )
        .await
        .expect("re-open the owner's minted fed-ID")
        .0
    }
}

/// Bind the responsible party — the serve-only floor refuses every route here on
/// an owner-UNBOUND node, and the owner's key IS the chat identity.
async fn bind_owner(engine: &Engine, owner: &OwnerIdentity) {
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": owner.key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize owner envelope");
    let record = KeyRecord {
        key_id: owner.key_id.clone(),
        // THE MINTED pubkeys, not a fixture's own seeds: the capsule signs with
        // the key on disk, and a directory row carrying anything else would make
        // every message the owner sends fail verification at the boundary.
        pubkey_ed25519_base64: owner.pubkey_ed25519_base64.clone(),
        pubkey_ml_dsa_65_base64: Some(owner.pubkey_ml_dsa_65_base64.clone()),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: owner.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: owner.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register responsible-party user key");

    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let node = node_key_id(engine).await;
    ciris_server::auth::ownership::emit_steward_binding(
        engine,
        &owner.signer().await,
        &node,
        &scopes,
    )
    .await
    .expect("emit owner-binding delegates_to(user -> node, infra:*)");
}

/// Bind a device to `CONTACT_KEY_ID` so `POST /v1/contacts` has a real
/// occurrence to resolve (an empty array would let the resolution be a no-op and
/// still pass). The occurrence key is FK'd to `federation_keys`, so it is a
/// registered key in its own right — as a real device key is.
async fn seed_contact_occurrence(engine: &Engine) {
    seed_user_key(engine, CONTACT_OCCURRENCE_KEY_ID, 0xB2, 0xB3).await;
    engine
        .federation_directory()
        .put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: CONTACT_KEY_ID.to_string(),
            occurrence_key_id: CONTACT_OCCURRENCE_KEY_ID.to_string(),
            device_class: "phone".to_string(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("bind the contact's phone occurrence");
}

/// Mint an active `wa_cert` + a bound session bearer token.
async fn mint_session(engine: &Engine, wa_id: &str, role: WaRole) -> String {
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.to_string(),
        name: wa_id.to_string(),
        role,
        pubkey: BASE64.encode([0u8; 32]),
        jwt_kid: format!("kid-{wa_id}"),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: false,
        parent_wa_id: None,
        parent_signature: None,
        scopes: serde_json::json!([]),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Session,
        created: now,
        last_login: None,
        active: true,
    };
    store::upsert(engine, cert).await.expect("mint wa_cert");
    ciris_server::auth::session::test_support_issue_session_token(wa_id)
}

/// The CONSENT subjects (persist's revocation-folded list) — distinct from
/// `replication_peers_from_consent`, which since the #472 arc is the TRANSPORT
/// set (NODE-role subjects only, persons resolved through their bindings).
/// A person-subject grant is real consent the wire cannot dial; these tests
/// assert the CONSENT fact.
async fn consent_subjects(engine: &Engine, node: &str) -> Vec<String> {
    engine
        .federation_directory()
        .list_consent_peers(node)
        .await
        .expect("list_consent_peers")
}

/// The node's EDGE signer — the room record's authority.
///
/// Edge signs the pair room with its own `LocalSigner` type over the SAME
/// federation key the Engine holds, so this wraps the identical seeds the
/// fixture's engine signer uses (`0xA1` classical, `0xA2` ML-DSA-65) under the
/// identical `key_id`. Different material here would sign rooms the directory
/// cannot verify — the failure would look like a storage error rather than a
/// mismatched identity.
///
/// `SealedEd25519Signer` is disk-backed with no in-memory constructor, so each
/// call takes its own directory under the system temp dir; the path is unique
/// per process and test so two tests never adopt into the same keystore.
async fn node_edge_signer(engine: &Engine) -> Arc<ciris_edge::identity::LocalSigner> {
    let dir = keystore_dir("node");
    let classical =
        ciris_keyring::SealedEd25519Signer::adopt(NODE_KEY_ID.to_string(), dir, &[0xA1; 32])
            .expect("adopt the node's sealed ed25519 key");
    let pqc = MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
        .expect("node ML-DSA-65 seed");
    // THE DERIVED id, never the alias: `signed_pair_community` stamps
    // `authority_key_id` from this verbatim, and persist verifies the room
    // against the attester's REGISTERED key (CIRISPersist#247).
    let key_id = engine
        .local_derived_key_id()
        .await
        .expect("the engine's derived federation key_id");
    Arc::new(ciris_edge::identity::LocalSigner::new(
        key_id,
        Arc::new(classical),
        Some(Arc::new(pqc)),
    ))
}

/// Serve the contacts+chat router on an ephemeral port.
///
/// `seed_dir` is the owner's OWN seed directory, never a throwaway: the route
/// opens the author's key out of this path, so handing it an empty directory is
/// the same as having no owner key at all.
async fn serve(engine: Arc<Engine>, seed_dir: PathBuf) -> (String, tokio::task::JoinHandle<()>) {
    let signer = node_edge_signer(&engine).await;
    let app = contacts_chat::router(engine, signer, seed_dir);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// The whole fixture: a claimed node, a registered contact with a device, an
/// owner session — and the owner's minted identity, which the caller needs
/// because the owner's key id is no longer knowable at compile time.
async fn fixture() -> (
    Arc<Engine>,
    String,
    String,
    OwnerIdentity,
    tokio::task::JoinHandle<()>,
) {
    let engine = node().await;
    let owner_id = OwnerIdentity::mint().await;
    register_self(&engine).await;
    bind_owner(&engine, &owner_id).await;
    seed_user_key(&engine, CONTACT_KEY_ID, 0xB0, 0xB1).await;
    seed_user_key(&engine, STRANGER_A_KEY_ID, 0xC0, 0xC1).await;
    seed_user_key(&engine, STRANGER_B_KEY_ID, 0xD0, 0xD1).await;
    seed_contact_occurrence(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, handle) = serve(Arc::clone(&engine), owner_id.seed_dir.clone()).await;
    (engine, base, owner, owner_id, handle)
}

/// `GET /v1/contacts` as the owner, decoded.
async fn contacts_list(client: &reqwest::Client, base: &str, owner: &str) -> serde_json::Value {
    let resp = client
        .get(format!("{base}/v1/contacts"))
        .bearer_auth(owner)
        .send()
        .await
        .expect("GET /v1/contacts");
    assert_eq!(resp.status(), 200);
    resp.json().await.expect("contacts json")
}

/// The revocation-FOLDED live grants this node holds for `peer` — persist's
/// `list_live_consent_grants_by` filtered to the peer. This is the read that
/// decides what actually replicates, so it is the read the widening tests
/// assert on: the HTTP response says what the server BELIEVES, this says what
/// the corpus holds.
async fn live_grants_for(
    engine: &Engine,
    node: &str,
    peer: &str,
) -> Vec<ciris_persist::federation::types::Attestation> {
    engine
        .federation_directory()
        .list_live_consent_grants_by(node)
        .await
        .expect("list_live_consent_grants_by")
        .into_iter()
        .filter(|a| a.subject_key_ids.iter().any(|s| s == peer))
        .collect()
}

/// A standing grant that does NOT cover `chat:` — the precondition the widening
/// tests are about.
///
/// Spelled out here rather than taken from
/// [`ciris_server::peer::default_attestation_prefixes`], because the peering
/// DEFAULT is free to widen (it is edge's `DEFAULT_CONSENT_PREFIXES`, and it now
/// carries `chat:` itself). A "narrow" set derived from a constant that may
/// already be wide is not narrow — the premise would evaporate and the tests
/// would keep passing while proving nothing.
fn narrow_peering_prefixes() -> Vec<String> {
    vec!["capacity:".to_string(), "trace:".to_string()]
}

/// What `POST /v1/contacts` guarantees a contact's grant covers: the peering
/// default, PLUS `chat:` — computed from the same two sources `add_contact`
/// reads, never restated as a literal list. A literal here would fork from the
/// default the moment the default moved, which is exactly the failure mode the
/// single-sourcing of that constant exists to prevent.
fn contact_grant_prefixes() -> Vec<String> {
    let mut prefixes = ciris_server::peer::default_attestation_prefixes();
    prefixes.push(ciris_edge::chat::CHAT_ATTESTATION_PREFIX.to_string());
    ciris_server::peer::normalize_prefixes(&prefixes)
}

/// The sorted, deduped UNION of two prefix sets — what a widening must produce.
fn union_prefixes(a: &[String], b: &[String]) -> Vec<String> {
    let mut all: Vec<String> = a.to_vec();
    all.extend_from_slice(b);
    ciris_server::peer::normalize_prefixes(&all)
}

/// The prefix set the single live grant covers, sorted. Panics if the peer has
/// no live grant — an absent grant and an empty one are different facts and the
/// tests must not collapse them onto `vec![]`.
async fn live_grant_prefixes(engine: &Engine, node: &str, peer: &str) -> Vec<String> {
    let live = live_grants_for(engine, node, peer).await;
    assert_eq!(
        live.len(),
        1,
        "expected exactly one live consent grant for {peer}, found {}",
        live.len()
    );
    let mut prefixes: Vec<String> = live[0].attestation_envelope["payload"]["attestation_prefixes"]
        .as_array()
        .expect("attestation_prefixes array")
        .iter()
        .map(|v| v.as_str().expect("prefix string").to_owned())
        .collect();
    prefixes.sort();
    prefixes
}

// ─── The far side of the room ───────────────────────────────────────────────

async fn contact_edge_signer() -> Arc<ciris_edge::identity::LocalSigner> {
    let dir = keystore_dir("contact");
    let classical =
        ciris_keyring::SealedEd25519Signer::adopt(CONTACT_KEY_ID.to_string(), dir, &[0xB0; 32])
            .expect("adopt the contact's sealed ed25519 key");
    let pqc = MlDsa65SoftwareSigner::from_seed_bytes(&[0xB1; 32], format!("{CONTACT_KEY_ID}-pqc"))
        .expect("contact ML-DSA-65 seed");
    Arc::new(ciris_edge::identity::LocalSigner::new(
        // The contact is registered under its plain alias, not a derived id, so
        // that is what its rows must be attested under.
        CONTACT_KEY_ID.to_string(),
        Arc::new(classical),
        Some(Arc::new(pqc)),
    ))
}

/// A fresh sealed-keystore directory, unique per process and call.
fn keystore_dir(what: &str) -> PathBuf {
    static NTH: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ciris-chat-{what}-{}-{}",
        std::process::id(),
        NTH.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("keystore dir");
    dir
}

/// Put a row and place it in the room, speaking as `actor` — the fixture's copy
/// of the module's own private `share_in_room`, and deliberately the same two
/// steps in the same order (store, THEN share, so the crossing acts on bytes
/// that already exist).
async fn share_as(
    engine: &Engine,
    row: ciris_persist::federation::types::Attestation,
    room: &str,
    node: &ciris_edge::identity::LocalSigner,
    actor: &ciris_edge::identity::LocalSigner,
) -> String {
    use ciris_edge::replication::attestation_bind::{share, Shared, Signers, With};
    let dir = engine.federation_directory();
    dir.put_attestation(ciris_persist::federation::SignedAttestation {
        attestation: row.clone(),
    })
    .await
    .unwrap_or_else(|e| panic!("put {}: {e}", row.attestation_id));
    let crossing = share(
        &*dir,
        &row,
        With::Community {
            community_key_id: room.to_owned(),
        },
        ciris_edge::replication::attestation_bind::CrossingBasis::ProducerAuthority,
        Signers {
            node,
            actor: Some(actor),
        },
    )
    .await
    .expect("share the row with the room");
    match crossing.shared {
        Shared::Placed { attestation_id } | Shared::AlreadyThere { attestation_id } => {
            attestation_id
        }
        Shared::AwaitingActor {
            attestation_id,
            age_ms,
        } => panic!("row {attestation_id} still waits for its author's signer ({age_ms} ms)"),
    }
}

/// `POST /v1/contacts` + `POST /v1/chat`, then the CONTACT's half of the room's
/// MLS handshake — together, the precondition for the message tests.
///
/// From edge v20.0.0 a community body is SEALED, always, so a room only one side
/// has key material in is a room nobody can speak in: `send_message` answers 503
/// `chat.room_not_keyed_yet` for as long as the counterpart's row is missing, and
/// on a single-node fixture it is missing forever. The counterpart is a person
/// this fixture has to play, so it plays them — mints the contact's key material,
/// publishes their KeyPackage into the room as a row the CONTACT themself signs
/// (v39.0.0 will not let this node author another key's claim), and hands back
/// the material the creator's Welcome is joined with.
///
/// Returns the room id and that material; [`contact_room_key`] turns the material
/// into the key that opens what the owner sends.
async fn open_chat(
    client: &reqwest::Client,
    base: &str,
    owner: &str,
    engine: &Engine,
    owner_id: &OwnerIdentity,
) -> (String, ciris_edge::mls::cohort_group::CohortKeyMaterial) {
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200, "add contact: {:?}", resp.text().await);
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 200, "start chat: {:?}", resp.text().await);
    let json: serde_json::Value = resp.json().await.expect("start chat json");
    let community_id = json["community_id"]
        .as_str()
        .expect("community_id")
        .to_string();

    // WHICH HALF THE FIXTURE PUBLISHES, stated rather than assumed. `PairRole`
    // is order-free — it hands the smaller fed-ID the creator's role — so the
    // owner is the creator only because its minted alias sorts first. Were that
    // to change, the owner would become the joiner, its own KeyPackage would not
    // exist until a first send had already been refused, and this one-shot setup
    // would quietly stop keying the room.
    assert_eq!(
        ciris_edge::chat::PairRole::of(&owner_id.key_id, CONTACT_KEY_ID),
        ciris_edge::chat::PairRole::Creator,
        "the fixture publishes the JOINER's KeyPackage, which keys the room only \
         while the owner ({}) holds the creator's role against {CONTACT_KEY_ID}",
        owner_id.key_id
    );
    let (material, key_package) =
        ciris_edge::mls::cohort_group::mint_cohort_key_material(CONTACT_KEY_ID)
            .expect("mint the contact's MLS key material");
    let key_package = ciris_edge::mls::cohort_group::key_package_to_bytes(key_package)
        .expect("serialize the contact's KeyPackage");
    let contact = contact_edge_signer().await;
    let row = ciris_edge::chat::key_package_attestation(
        &contact,
        &owner_id.key_id,
        &key_package,
        chrono::Utc::now(),
    )
    .await
    .expect("the contact's KeyPackage row");
    let node = node_edge_signer(engine).await;
    share_as(engine, row, &community_id, &node, &contact).await;
    (community_id, material)
}

/// The CONTACT's view of the room key, once the owner's Welcome has landed.
///
/// This is the far side actually joining, not a re-derivation: the key comes out
/// of an MLS group built from the creator's Welcome and the SAME material whose
/// KeyPackage [`open_chat`] published. A body it opens is a body the other member
/// can genuinely read.
async fn contact_room_key(
    engine: &Engine,
    owner_id: &OwnerIdentity,
    community_id: &str,
    material: ciris_edge::mls::cohort_group::CohortKeyMaterial,
) -> ciris_edge::chat::RoomKey {
    let dir = engine.federation_directory();
    let (welcome, _epoch) = ciris_edge::chat::welcome_from(&*dir, &owner_id.key_id, community_id)
        .await
        .expect("read the creator's Welcome")
        .expect("the owner's send must have admitted the contact and shared a Welcome");
    let store = ciris_edge::mls::ScopeStateProvider::new(Arc::new(
        ciris_persist::encrypted_kv::XChaChaKvStore::open_in_memory(community_id.as_bytes())
            .expect("the contact's own MLS store"),
    ));
    let group = ciris_edge::mls::CohortGroup::join(store, community_id, material, &welcome, 16)
        .await
        .expect("join the room from the Welcome");
    ciris_edge::chat::RoomKey::of(&group)
        .await
        .expect("the room key, as the contact holds it")
}

// ─── 1. Add a contact by fedID ──────────────────────────────────────────────

#[tokio::test]
async fn add_contact_writes_the_consent_grant_and_resolves_occurrences() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("add contact json");
    assert_eq!(json["key_id"], CONTACT_KEY_ID);
    assert!(
        json["consent_attestation_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "the contact relationship IS the consent grant — its id must come back: {json}"
    );
    assert_eq!(json["freshly_emitted"], true);
    assert_eq!(
        json["occurrence_key_ids"],
        serde_json::json!([CONTACT_OCCURRENCE_KEY_ID]),
        "the contact's identity occurrence must be resolved from the directory"
    );

    // The grant is a real `consent:replication:v1` row this node authored, and
    // persist's revocation-folded projection can see it.
    let node = node_key_id(&engine).await;
    let peers = consent_subjects(&engine, &node).await;
    assert!(
        peers.iter().any(|p| p == CONTACT_KEY_ID),
        "the contact must land in the consent peer set: {peers:?}"
    );

    // Idempotent: a second add returns the SAME grant, freshly_emitted false.
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts (again)");
    assert_eq!(resp.status(), 200);
    let again: serde_json::Value = resp.json().await.expect("re-add json");
    assert_eq!(again["freshly_emitted"], false);
    assert_eq!(
        again["consent_attestation_id"],
        json["consent_attestation_id"]
    );

    // And it renders in the list, on the peer card the client already binds.
    let resp = client
        .get(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET /v1/contacts");
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.expect("contacts json");
    assert_eq!(list["total"], 1);
    let row = &list["contacts"][0];
    assert_eq!(row["key_id"], CONTACT_KEY_ID);
    assert_eq!(row["contact"], true);
    assert_eq!(row["chat_started"], false, "no chat opened yet");
    assert_eq!(
        row["chat_community_id"],
        serde_json::json!(pair_community_key_id(&owner_id.key_id, CONTACT_KEY_ID))
    );
    assert!(
        row["pubkey_ed25519_base64"].is_string(),
        "a contact card must carry the peer projection's fields: {row}"
    );
}

#[tokio::test]
async fn an_unknown_fed_id_is_refused_with_a_typed_reason() {
    let (_engine, base, owner, _owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": "nobody-v1" }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 404);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "contacts.unknown_fed_id");
}

/// **THE PR #464 P1 REGRESSION.** Give a peer a standing
/// `consent:replication:v1` grant that does NOT cover `chat:`, and only then add
/// them as a contact.
///
/// The narrowness is CONSTRUCTED here, and that is a change of provenance worth
/// stating: this used to be what an ordinary peering left behind, and it no
/// longer is — the peering default now carries `chat:` itself. A chat-less
/// standing grant today comes from an operator who narrowed one through
/// `POST /v1/federation/consent`, or from a peer federated before the default
/// widened. The PRIMITIVE under test is unchanged: a widening must supersede a
/// narrower live grant rather than report it as already sufficient, and that is
/// exercised by any grant narrower than the contact set, however it got narrow.
///
/// This is the case the old code got wrong, and it got it wrong in the direction
/// that hides: `emit_replication_consent`'s guard matched on (subject, dimension)
/// and returned the first hit without ever comparing prefixes, so `POST
/// /v1/contacts` answered 200 while `chat:` stayed uncovered. The contacts who
/// had peered first — the ones you actually know — were exactly the ones you
/// could not message. Nothing 404s, nothing 403s; the messages simply never
/// become eligible to replicate.
///
/// So the assertion is on the EFFECTIVE folded grant, not on the response: read
/// `list_live_consent_grants_by` back and demand `chat:` is in the payload of the
/// one grant that survives the fold.
#[tokio::test]
async fn adding_an_already_peered_key_widens_its_narrow_consent_grant() {
    let (engine, base, owner, _owner_id, _h) = fixture().await;
    let node = node_key_id(&engine).await;

    // The pre-existing peering grant, deliberately without `chat:`.
    let peered = ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &narrow_peering_prefixes(),
    )
    .await
    .expect("pre-existing federation peering grant");
    assert!(peered.freshly_emitted);
    assert_eq!(
        live_grant_prefixes(&engine, &node, CONTACT_KEY_ID).await,
        narrow_peering_prefixes(),
        "the fixture must actually start NARROW (no chat:), or this test proves \
         nothing"
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    let status = resp.status();
    let body = resp.text().await.expect("add contact body");
    assert_eq!(status, 200, "add contact: {body}");
    let json: serde_json::Value = serde_json::from_str(&body).expect("add contact json");
    assert_eq!(
        json["superseded_attestation_id"],
        serde_json::json!(peered.attestation_id),
        "the widening must NAME the narrower grant it retires: {json}"
    );
    assert_eq!(json["freshly_emitted"], true);
    assert_ne!(
        json["consent_attestation_id"],
        serde_json::json!(peered.attestation_id)
    );

    // THE assertion: the EFFECTIVE folded grant covers chat:, and it is the ONLY
    // live grant for this peer.
    assert_eq!(
        live_grant_prefixes(&engine, &node, CONTACT_KEY_ID).await,
        union_prefixes(&narrow_peering_prefixes(), &contact_grant_prefixes()),
        "the widened grant must carry the UNION — dropping capacity:/trace: would \
         trade one dead plane for two"
    );
    assert!(
        live_grant_prefixes(&engine, &node, CONTACT_KEY_ID)
            .await
            .iter()
            .any(|p| p == ciris_edge::chat::CHAT_ATTESTATION_PREFIX),
        "and it must cover chat: — the whole point of the widening"
    );
    let live = live_grants_for(&engine, &node, CONTACT_KEY_ID).await;
    assert_eq!(live.len(), 1, "exactly one grant may be live for a peer");
    assert_eq!(live[0].attestation_id, json["consent_attestation_id"]);

    // The contact is still a contact — a widening must not drop the peer out of
    // the revocation-folded set on its way through.
    let peers = consent_subjects(&engine, &node).await;
    assert!(peers.iter().any(|p| p == CONTACT_KEY_ID), "{peers:?}");

    // And a SECOND add is now a true no-op: nothing written, nothing superseded.
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts (again)");
    assert_eq!(resp.status(), 200);
    let again: serde_json::Value = resp.json().await.expect("re-add json");
    assert_eq!(
        again["freshly_emitted"], false,
        "second add must be a no-op: {again}"
    );
    assert!(again["superseded_attestation_id"].is_null());
    assert_eq!(
        again["consent_attestation_id"],
        json["consent_attestation_id"]
    );
    assert_eq!(
        live_grants_for(&engine, &node, CONTACT_KEY_ID).await.len(),
        1,
        "a no-op must not append a grant"
    );
}

/// A widening PRESERVES the operator's policy on every axis but prefixes. An
/// owner who narrowed the audience or time-boxed the grant through
/// `POST /v1/federation/consent` must not have that reverted by someone adding a
/// contact — a silent policy reset is the same class of defect as the silent
/// no-op, just pointing the other way.
#[tokio::test]
async fn widening_preserves_the_standing_grants_policy() {
    let (engine, base, owner, _owner_id, _h) = fixture().await;
    let node = node_key_id(&engine).await;
    let opts = ciris_server::peer::ConsentGrantOptions {
        audience: Some(cohort_scope::SPECIES.to_string()),
        principle: Some("analyze".to_string()),
        purpose: Some("a purpose the owner wrote down".to_string()),
        ..Default::default()
    };
    ciris_server::peer::emit_replication_consent_with_policy(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &["trace:"],
        &opts,
    )
    .await
    .expect("owner-policy grant");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    let status = resp.status();
    let body = resp.text().await.expect("add contact body");
    assert_eq!(status, 200, "add contact: {body}");

    let live = live_grants_for(&engine, &node, CONTACT_KEY_ID).await;
    assert_eq!(live.len(), 1);
    let payload = &live[0].attestation_envelope["payload"];
    assert_eq!(payload["audience"], cohort_scope::SPECIES);
    assert_eq!(payload["principle"], "analyze");
    assert_eq!(payload["purpose"], "a purpose the owner wrote down");
    // The prefix axis DID move — that is the point of the call — to the union of
    // the standing `trace:` and what `add_contact` requires. Every other axis
    // above is unchanged, which is the property this test exists for.
    assert_eq!(
        payload["attestation_prefixes"],
        serde_json::json!(union_prefixes(
            &["trace:".to_string()],
            &contact_grant_prefixes()
        )),
        "the union must be sorted + deduped so the JCS bytes are stable"
    );
}

/// Withdraw a consent grant the way the CEG says to: a `withdraws` composer over
/// the grant's `attestation_id`, authored by the grant's own author (this node).
///
/// Built through persist's OWN `withdraws_attestation_envelope` rather than a
/// hand-rolled object — the same builder `admin_ops::emit_about_peer` uses — so
/// the test cannot pass against an envelope shape production never writes. Note
/// it emits no `dimension`, which is the same rule the widening composer obeys.
///
/// `subject_key_ids` stays EMPTY on purpose: the node is the grant's PRODUCER,
/// not its subject, so this is not a §10.1.3 subject-side revocation and needs
/// no bound-hybrid signature. A withdraw naming itself as subject would.
async fn withdraw_consent_grant(engine: &Engine, peer: &str, grant_attestation_id: &str) {
    let envelope = ciris_persist::federation::withdraws_attestation_envelope(
        grant_attestation_id,
        attestation_type::SCORES,
    );
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
        .expect("withdraws envelope");
    let mut input = ciris_persist::federation::EmitAttestationInput::with_envelope(
        attestation_type::WITHDRAWS,
        core,
        cohort_scope::FEDERATION.to_string(),
    );
    input.attested_key_id = Some(peer.to_string());
    engine
        .emit_attestation_self(input)
        .await
        .expect("withdraw the consent grant");
}

/// **REVOCATION MUST BE FREE.** The guard that decides whether a grant already
/// stands used to scan `list_attestations_by`, which folds nothing — so a
/// WITHDRAWN grant still answered "already present", and `emit_replication_consent`
/// returned success having written nothing. Withdrawing consent to a peer
/// permanently poisoned re-consenting to them: every later peering call was a
/// silent no-op with no live grant behind it.
///
/// A revocation that costs you the ability to ever re-consent is one nobody can
/// afford to exercise, which makes it not a revocation at all. This pins the
/// primitive directly — `emit_replication_consent`, the call peering and boot
/// make — rather than only the route on top of it.
#[tokio::test]
async fn emit_replication_consent_re_grants_after_a_withdraw() {
    let (engine, _base, _owner, _owner_id, _h) = fixture().await;
    let node = node_key_id(&engine).await;

    let first = ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("first grant");
    assert!(first.freshly_emitted);
    assert_eq!(
        live_grants_for(&engine, &node, CONTACT_KEY_ID).await.len(),
        1
    );

    withdraw_consent_grant(&engine, CONTACT_KEY_ID, &first.attestation_id).await;

    // The withdraw must actually have landed, or the re-grant below proves
    // nothing about the fold.
    assert!(
        live_grants_for(&engine, &node, CONTACT_KEY_ID)
            .await
            .is_empty(),
        "the withdraw must clear the live grant"
    );
    let peers = consent_subjects(&engine, &node).await;
    assert!(!peers.iter().any(|p| p == CONTACT_KEY_ID), "{peers:?}");

    // RE-CONSENT. Under the old guard this returned freshly_emitted:false and
    // wrote nothing, leaving the peer permanently unreachable.
    let second = ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("re-grant after withdraw");
    assert!(
        second.freshly_emitted,
        "re-consenting after a withdraw must write a real grant, not report the withdrawn one"
    );
    assert_ne!(second.attestation_id, first.attestation_id);
    let live = live_grants_for(&engine, &node, CONTACT_KEY_ID).await;
    assert_eq!(live.len(), 1, "exactly one live grant after re-consent");
    assert_eq!(live[0].attestation_id, second.attestation_id);
    let peers = consent_subjects(&engine, &node).await;
    assert!(
        peers.iter().any(|p| p == CONTACT_KEY_ID),
        "the peer must be replicable again: {peers:?}"
    );
}

/// The same property through the CONTACTS route: un-contact someone, then add
/// them back. The user-visible shape of the defect above — "I removed them and
/// now I can't add them again", with the UI reporting success every time.
#[tokio::test]
async fn re_adding_an_un_contacted_person_restores_a_live_grant() {
    let (engine, base, owner, _owner_id, _h) = fixture().await;
    let node = node_key_id(&engine).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200);
    let first: serde_json::Value = resp.json().await.expect("add contact json");
    let first_id = first["consent_attestation_id"]
        .as_str()
        .expect("id")
        .to_string();

    // Un-contact: the ordinary CEG withdraw of the grant row, which is what the
    // module doc promises un-contacting IS.
    withdraw_consent_grant(&engine, CONTACT_KEY_ID, &first_id).await;
    let listed = contacts_list(&client, &base, &owner).await;
    assert_eq!(
        listed["total"], 0,
        "a withdrawn contact must leave the list: {listed}"
    );

    // Add them back.
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts (re-add)");
    let status = resp.status();
    let body = resp.text().await.expect("re-add body");
    assert_eq!(status, 200, "re-add: {body}");
    let second: serde_json::Value = serde_json::from_str(&body).expect("re-add json");
    assert_eq!(
        second["freshly_emitted"], true,
        "re-add must write a grant: {second}"
    );
    assert_ne!(
        second["consent_attestation_id"],
        serde_json::json!(first_id)
    );
    assert!(
        second["superseded_attestation_id"].is_null(),
        "a re-grant is not a widening — there was nothing live to supersede"
    );
    assert_eq!(
        live_grant_prefixes(&engine, &node, CONTACT_KEY_ID).await,
        contact_grant_prefixes(),
        "a re-grant must restore the FULL contact coverage, chat: included"
    );
    let listed = contacts_list(&client, &base, &owner).await;
    assert_eq!(listed["total"], 1, "the contact must be back: {listed}");
    assert_eq!(listed["contacts"][0]["key_id"], CONTACT_KEY_ID);
}

// ─── 2. Chat creation converges ─────────────────────────────────────────────

#[tokio::test]
async fn chat_creation_is_convergent_and_idempotent_for_a_pair() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;

    // THE convergence property: the id is derived from public inputs alone, so
    // the other end computes the same one without ever talking to this node —
    // in either argument order.
    assert_eq!(
        community_id,
        pair_community_key_id(&owner_id.key_id, CONTACT_KEY_ID)
    );
    assert_eq!(
        community_id,
        pair_community_key_id(CONTACT_KEY_ID, &owner_id.key_id),
        "a room the two ends can only reach by agreeing who initiated is not a room"
    );

    // The row is a real 2-member persist Community.
    let community = engine
        .federation_directory()
        .lookup_community(&community_id)
        .await
        .expect("lookup_community")
        .expect("the community must exist after POST /v1/chat");
    let mut members: Vec<String> = community.members.iter().map(|m| m.key_id.clone()).collect();
    members.sort();
    let mut expected = vec![owner_id.key_id.clone(), CONTACT_KEY_ID.to_string()];
    expected.sort();
    assert_eq!(members, expected);

    // Idempotent: a second start returns the same room, not a second one.
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat (again)");
    assert_eq!(resp.status(), 200);
    let again: serde_json::Value = resp.json().await.expect("start chat json");
    assert_eq!(again["community_id"], serde_json::json!(community_id));
    assert_eq!(again["freshly_created"], false);
    assert_eq!(again["cohort_scope"], cohort_scope::COMMUNITY);
}

#[tokio::test]
async fn a_chat_with_a_non_contact_is_refused() {
    let (_engine, base, owner, _owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    // STRANGER_A is a registered key but was never added as a contact — so this
    // node has consented to replicate nothing to them, and a room whose messages
    // never leave is not a chat.
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": STRANGER_A_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 403);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.not_a_contact");
}

// ─── 3. Send + list round-trips, with the CEG identity intact ───────────────

#[tokio::test]
async fn send_and_list_round_trip_carries_the_hamburger_fields() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;

    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "first" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200, "send: {:?}", resp.text().await);
    let sent: serde_json::Value = resp.json().await.expect("send json");
    let first_id = sent["attestation_id"]
        .as_str()
        .expect("attestation_id")
        .to_string();
    assert_eq!(sent["cohort_scope"], cohort_scope::COMMUNITY);

    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "second", "content_type": "text/plain" }))
        .send()
        .await
        .expect("POST message 2");
    assert_eq!(resp.status(), 200);
    let second_id = resp.json::<serde_json::Value>().await.expect("send json")["attestation_id"]
        .as_str()
        .expect("attestation_id")
        .to_string();

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.expect("messages json");
    assert_eq!(list["total"], 2, "both messages must come back: {list}");
    let messages = list["messages"].as_array().expect("messages array");

    // NEWEST LAST — a transcript reads down the page. The order is asserted on
    // the row IDENTITIES, because from edge v20.0.0 the projection's `body` is
    // the SEALED body and no longer distinguishes them by eye.
    assert_eq!(messages[0]["attestation_id"], serde_json::json!(first_id));
    assert_eq!(messages[1]["attestation_id"], serde_json::json!(second_id));

    // THE ROUND TRIP, END TO END: what the owner sent is what the OTHER MEMBER
    // reads. The plaintext never appears on the plane — the projection carries
    // ciphertext — so the words are recovered the only way anyone can recover
    // them, by joining the room from the creator's Welcome and opening the rows
    // with the key that join yields. A test that read `body` off the response
    // would now be asserting on base64 and would pass on a broken seal.
    // THE PLANE carries ciphertext; the READER opens it. Both halves are
    // asserted, because either alone is satisfiable by a broken system: a
    // projection that returns base64 would pass a "no plaintext" check while
    // being useless, and a plaintext row would pass a "reader can read it" check
    // while leaking to every peer that ever replicates it.
    let stored = engine
        .federation_directory()
        .list_attestations_by(&owner_id.key_id)
        .await
        .expect("list the owner's rows")
        .into_iter()
        .find(|a| a.attestation_id == first_id)
        .expect("the placed row");
    assert_ne!(
        stored
            .attestation_envelope
            .get("body")
            .and_then(|v| v.as_str()),
        Some("first"),
        "the plane must never carry a community body in plaintext: {:?}",
        stored.attestation_envelope
    );
    assert!(
        stored.attestation_envelope.get("sealed").is_some(),
        "a sealed body must carry its seal header, or no reader can open it: {:?}",
        stored.attestation_envelope
    );
    assert_eq!(
        messages[0]["body"], "first",
        "the room's own member must READ what they sent — the projection opens \
         the seal (chat::ChatMessage::from_row): {messages:?}"
    );
    let key = contact_room_key(&engine, &owner_id, &community_id, contact_material).await;
    let opened = ciris_edge::chat::messages_in_room(
        &*engine.federation_directory(),
        &[owner_id.key_id.clone(), CONTACT_KEY_ID.to_string()],
        &community_id,
        &key,
    )
    .await
    .expect("read the room as the contact");
    assert_eq!(
        opened
            .iter()
            .map(|m| (m.attestation_id.as_str(), m.body.clone()))
            .collect::<Vec<_>>(),
        vec![
            (
                first_id.as_str(),
                ciris_edge::chat::Body::Text("first".to_string())
            ),
            (
                second_id.as_str(),
                ciris_edge::chat::Body::Text("second".to_string())
            ),
        ],
        "both messages must open, in order, for the room's other member"
    );

    // THE HAMBURGER FIELDS. The client renders each message with the same
    // attestation card it uses everywhere else; a bespoke `{from,text,at}` would
    // have hidden every one of these.
    let m = &messages[0];
    assert_eq!(m["attestation_id"], serde_json::json!(first_id));
    // THE HUMAN ATTESTS AND AUTHORS — one key, and it is in the SIGNATURE. The
    // node used to attest with the author riding in an envelope member, which
    // made a reader trust the box about whose words these were; since the
    // signer-explicit send the two fields answer with the same person, and
    // `author` is no longer a claim anyone could have written.
    assert_eq!(m["attesting_key_id"], serde_json::json!(owner_id.key_id));
    assert_eq!(m["attested_key_id"], serde_json::json!(owner_id.key_id));
    assert_eq!(m["author"], owner_id.key_id);
    assert_eq!(m["attestation_type"], attestation_type::SCORES);
    assert_eq!(m["cohort_scope"], cohort_scope::COMMUNITY);
    assert_eq!(m["community_id"], serde_json::json!(community_id));
    assert_eq!(m["status"], "live");
    assert_eq!(
        m["subject_key_ids"],
        serde_json::json!([owner_id.key_id]),
        "a community placement is a producer's claim about their OWN content, so \
         the row names nobody else"
    );
    assert_eq!(m["content_type"], "text/plain");
    assert_eq!(m["mine"], true);
    assert!(m["asserted_at"].is_string());
}

#[tokio::test]
async fn a_withdrawn_message_reads_back_as_withdrawn() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;

    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "oops" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200);
    let sent: serde_json::Value = resp.json().await.expect("send json");
    let message_id = sent["attestation_id"]
        .as_str()
        .expect("attestation_id")
        .to_string();

    // The author withdraws it — the ordinary CEG composer, emitted the same way
    // the route emits the message it targets.
    withdraw_own_message(&engine, &owner_id, &community_id, &message_id).await;

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    let list: serde_json::Value = resp.json().await.expect("messages json");
    let m = &list["messages"][0];
    assert_eq!(
        m["status"], "withdrawn",
        "the read must fold the composer, not report the raw row: {list}"
    );
    assert!(m["status_attestation_id"].is_string());
}

// ─── 4. THE contextual-integrity line ───────────────────────────────────────

/// A community of two strangers, authored by this node (as a replicated row
/// would be), holding a real message. The owner is deliberately not on it.
async fn strangers_community(engine: &Engine) -> (String, LocalSigner, String) {
    use ciris_persist::federation::types::{Community, CommunityMember};
    let (a_signer, a_key_id) = stranger_a_identity();
    seed_user_key_at(engine, &a_key_id, 0xC0, 0xC1).await;
    let community_id = pair_community_key_id(&a_key_id, STRANGER_B_KEY_ID);
    let now = chrono::Utc::now();
    engine
        .put_community_self_signed(Community {
            community_key_id: community_id.clone(),
            community_name: format!("{a_key_id} <-> {STRANGER_B_KEY_ID}"),
            members: [a_key_id.as_str(), STRANGER_B_KEY_ID]
                .iter()
                .map(|k| CommunityMember {
                    key_id: (*k).to_string(),
                    joined_at: now,
                    role: None,
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "unanimous".to_string(),
            policy_blob: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("author the strangers' community");
    (community_id, a_signer, a_key_id)
}

/// A message row with the attester named, and its signer when that attester
/// is not this node. v39.0.0 will not let this node author another key's claim,
/// so a message placed in a room this node is not in has to be signed by someone
/// who is in it.
async fn seed_message_as(
    engine: &Engine,
    node: &str,
    actor: Option<&LocalSigner>,
    author: &str,
    community_id: &str,
    body: &str,
) -> String {
    let node = node.to_string();
    let envelope = serde_json::json!({
        (paths::DIMENSION): contacts_chat::CHAT_MESSAGE_DIMENSION,
        "community_id": community_id,
        "on_behalf_of_key_id": author,
        "body": body,
        "content_type": "text/plain",
        "score": 1.0,
    });
    let input = LocalAttestationInput {
        attestation_id: None,
        attesting_key_id: node.clone(),
        attested_key_id: Some(node.clone()),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        expires_at: None,
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            envelope,
        )
        .expect("envelope"),
        subject_key_ids: vec![node],
        cohort_scope: cohort_scope::SELF.to_string(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    let id = engine
        .federation_directory()
        .attestation_upsert_local(input)
        .await
        .expect("upsert seeded chat message");
    let outcome = ciris_server::attestation_crossing::enter_mesh_at(
        engine,
        &id,
        &Audience::Community {
            community_key_id: community_id.to_string(),
        },
        &CrossingBasis::ProducerAuthority,
        actor,
    )
    .await
    .expect("promote seeded chat message to the community tier");
    // THE PLACED ROW'S ID, not the local one. The widening writes a new row and
    // that is what the community reads back, so a fixture returning the local id
    // hands its test an id no transcript will ever contain.
    ciris_server::attestation_crossing::placed_id(&outcome)
        .expect("the seeded message must reach the community")
        .to_owned()
}

/// The owner's `withdraws` composer over one of their own messages.
///
/// **This one cannot be signature-deferred.** `is_subject_side_revocation`
/// classifies a `withdraws` whose attester is in its own `subject_key_ids` as a
/// TRANSIT revocation (§10.1.3 / AV-61), and the local door then demands a
/// bound-hybrid signature that verifies against the attester's REGISTERED
/// pubkeys before it will store the row. So the withdraw is signed here with the
/// owner's own key — which is exactly the constraint the client faces: the
/// server can stage a message on the owner's behalf, but only the holder of the
/// owner's key can retract one.
async fn withdraw_own_message(
    engine: &Engine,
    owner: &OwnerIdentity,
    community_id: &str,
    target_attestation_id: &str,
) {
    // OWNER-attested, like the message it retracts. From edge v20.0.0 a chat row
    // is attested by the HUMAN (`chat_message_attestation(author, ..)`), and
    // `collect_messages` walks the ROSTER to find composers — so the pre-v39
    // node-attested form this fixture used to build is invisible to the read
    // path, which is correct rather than a gap: a withdraw no member attested is
    // not a member's withdraw.
    let envelope = serde_json::json!({
        (paths::DIMENSION): contacts_chat::CHAT_MESSAGE_DIMENSION,
        (paths::REFERENCES_ATTESTATION_ID): target_attestation_id,
    });
    let input = LocalAttestationInput {
        attestation_id: None,
        attesting_key_id: owner.key_id.clone(),
        attested_key_id: Some(owner.key_id.clone()),
        attestation_type: attestation_type::WITHDRAWS.to_string(),
        weight: None,
        expires_at: None,
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            envelope,
        )
        .expect("withdraw envelope"),
        // EMPTY, and load-bearing: `is_subject_side_revocation` classifies a
        // `withdraws` whose attester is among its own subjects as a §10.1.3
        // TRANSIT revocation, which the local door then demands a bound-hybrid
        // signature for. Naming nobody keeps it an ordinary durable row — and
        // matches persist's own `consent_peer_set` fixture composer.
        subject_key_ids: Vec::new(),
        cohort_scope: cohort_scope::SELF.to_string(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    let id = engine
        .federation_directory()
        .attestation_upsert_local(input)
        .await
        .expect("upsert withdraws");

    // THE CROSSING NEEDS THE OTHER KEYING. Same hardware material as
    // `OwnerIdentity::signer()`, keyed for `custody_for` — see
    // `identity::hardware_user_crossing_signer`. The ordinary user signer derives
    // twice here and the widening is refused.
    let crossing = ciris_server::identity::hardware_user_crossing_signer(
        ciris_server::identity::UserIdentityBackend::Software,
        &owner.alias,
        owner.seed_dir.clone(),
    )
    .await
    .expect("the owner's crossing signer");
    assert_eq!(
        crossing.derived_key_id(),
        owner.key_id,
        "the crossing signer must derive to the id the withdraw is attested under, \
         or `custody_for` can never accept the owner as the actor"
    );

    let outcome = ciris_server::attestation_crossing::enter_mesh_at(
        engine,
        &id,
        &Audience::Community {
            community_key_id: community_id.to_string(),
        },
        &CrossingBasis::ProducerAuthority,
        Some(&crossing),
    )
    .await
    .expect("promote withdraws");
    assert!(
        ciris_server::attestation_crossing::is_placed(&outcome),
        "the withdraw never reached the room: {outcome:?}"
    );
}

/// **The test that matters.** The node's OWNER — the highest authority this
/// process answers to — asks for a community they are not a member of, and the
/// substrate's own §4.3 predicate refuses. If this ever returns 200, the
/// `community` tier is decorative.
#[tokio::test]
async fn a_non_member_cannot_read_the_communitys_messages() {
    let (engine, base, owner, _owner_id, _h) = fixture().await;
    let (community_id, a_signer, a_key_id) = strangers_community(&engine).await;
    let secret = "the strangers' private message";
    seed_message_as(
        &engine,
        &a_key_id,
        Some(&a_signer),
        &a_key_id,
        &community_id,
        secret,
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(
        resp.status(),
        403,
        "owning the node is not membership in the cohort"
    );
    let body = resp.text().await.expect("refusal body");
    let json: serde_json::Value = serde_json::from_str(&body).expect("refusal json");
    assert_eq!(json["reason_id"], "chat.not_a_member");
    assert!(
        !body.contains(secret),
        "the refusal must not leak the content it is withholding: {body}"
    );

    // And the write side refuses too — a non-member cannot speak into the room
    // either.
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "let me in" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 403);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.not_a_member");
}

/// **The control.** Without it the refusal above could pass because the fixture
/// never worked — an unclaimed node, an unregistered key, a community that was
/// never written all produce the same 403 for reasons having nothing to do with
/// membership.
#[tokio::test]
async fn the_owner_reads_their_own_community() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;
    // The SAME seeding path the withheld community used, so the two tests differ
    // in exactly one variable: whether the caller is on the roster.
    // SENT THROUGH THE ROUTE, not seeded. A hand-built row cannot stand in for
    // this any more: the producer seals the body under the room key and signs it
    // as the person, and reading it back is the half being tested. A fixture row
    // would prove the reader can open something the producer never made.
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "hello" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200, "send: {:?}", resp.text().await);

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(resp.status(), 200);
    let list: serde_json::Value = resp.json().await.expect("messages json");
    assert_eq!(list["total"], 1);
    assert_eq!(list["messages"][0]["body"], "hello");
    assert_eq!(list["messages"][0]["mine"], true, "the owner's own words");
}

#[tokio::test]
async fn an_unknown_community_is_a_404_not_a_403() {
    let (_engine, base, owner, _owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/v1/chat/chat:pair:v1:deadbeef/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(resp.status(), 404);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.unknown_community");
}

// ─── The delegate ruling, and the substrate pin under it ────────────────────

/// Mint a DELEGATED bearer — the `dgrant:` token a device-grant issues after the
/// owner approves. It carries the owner's role AND `FullAccess` by design, so the
/// owner gate cannot tell it from the owner; only `caller.actor` can.
///
/// The bearer alone is not the authority: `resolve_bearer` RE-CHECKS the signed
/// `delegates_to(owner -> actor)` edge in the graph on every use (so revoking the
/// delegation kills the token immediately), which is why this emits the real edge
/// first rather than only registering the in-memory grant.
async fn mint_delegated_token(
    engine: &Engine,
    owner_id: &OwnerIdentity,
    owner_wa_id: &str,
    client_id: &str,
) -> String {
    // The durable, owner-signed act-on-behalf edge — built through persist's own
    // envelope helper and the user-signed emit path device_grant's approve uses.
    ciris_server::auth::ownership::emit_signed_attestation(
        engine,
        &owner_id.signer().await,
        attestation_type::DELEGATES_TO,
        client_id,
        ciris_persist::federation::delegates_to_envelope(
            client_id,
            &[DELEGATED_SCOPE.to_string()],
            false,
        ),
        None,
    )
    .await
    .expect("emit delegates_to(owner -> actor)");
    mint_delegated_token_inner(
        owner_id,
        owner_wa_id,
        client_id,
        DelegationConstraints::default(),
    )
}

/// The same, with an owner-set ALLOW-LIST — the case codex named: a delegate
/// granted one verb and reaching for the others.
async fn mint_constrained_delegated_token(
    engine: &Engine,
    owner_id: &OwnerIdentity,
    owner_wa_id: &str,
    client_id: &str,
    allow: &[&str],
) -> String {
    ciris_server::auth::ownership::emit_signed_attestation(
        engine,
        &owner_id.signer().await,
        attestation_type::DELEGATES_TO,
        client_id,
        ciris_persist::federation::delegates_to_envelope(
            client_id,
            &[DELEGATED_SCOPE.to_string()],
            false,
        ),
        None,
    )
    .await
    .expect("emit delegates_to(owner -> actor)");
    mint_delegated_token_inner(
        owner_id,
        owner_wa_id,
        client_id,
        DelegationConstraints {
            actions_allow: Some(allow.iter().map(|s| (*s).to_string()).collect()),
            ..Default::default()
        },
    )
}

const DELEGATED_SCOPE: &str = "owner:act-on-behalf";

fn mint_delegated_token_inner(
    owner_id: &OwnerIdentity,
    owner_wa_id: &str,
    client_id: &str,
    constraints: DelegationConstraints,
) -> String {
    use ciris_server::auth::session::DelegatedGrant;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    ciris_server::auth::session::register_delegated_grant(DelegatedGrant {
        owner_wa_id: owner_wa_id.to_string(),
        owner_role: ciris_server::auth::roles::UserRole::SystemAdmin,
        owner_key_id: owner_id.key_id.clone(),
        client_id: client_id.to_string(),
        scope: DELEGATED_SCOPE.to_string(),
        expires_at: now + 600,
        issued_at: now,
        purpose: Some("a monitoring agent".to_string()),
        attestation_id: None,
        constraints,
    })
}

/// **A DELEGATE MAY NOT AUTHOR A MESSAGE.** The ruling, pinned.
///
/// The gate passes delegates by design, so this has to be decided rather than
/// inherited, and the code decides it: the node holds only the OWNER's key, so
/// signing as the delegate is not possible — and signing as the OWNER from a
/// delegated session mints a signature that OUTLIVES the delegation. Withdrawing
/// the `delegates_to` edge cannot retract bytes already signed under the owner's
/// key, so the message would stand as the owner's own words forever. That is the
/// class CIRISServer#342's capsule doc names, which is why `ChatAuthor` sits on
/// `never_delegatable` beside re-delegation, wipe and the accord kill-switch.
///
/// READS stay open to a delegate: reading is bounded by the delegation's life,
/// and the cohort gate still applies underneath.
#[tokio::test]
async fn a_delegate_may_not_author_a_message_but_may_read() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;
    let delegated = mint_delegated_token(&engine, &owner_id, "wa-owner", CONTACT_KEY_ID).await;

    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&delegated)
        .json(&serde_json::json!({ "body": "signed as whom, exactly?" }))
        .send()
        .await
        .expect("POST message as a delegate");
    assert_eq!(
        resp.status(),
        403,
        "a delegate must not author under the owner's key"
    );
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.delegate_may_not_author");

    // The same bearer READS fine — the refusal is about signing, not about trust.
    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&delegated)
        .send()
        .await
        .expect("GET messages as a delegate");
    assert_eq!(
        resp.status(),
        200,
        "a delegate may read what it may not author"
    );
}

/// **EVERY OWNER-GATED ROUTE ANSWERS TO A VERB.** The other half of the
/// delegation hole: `resolve_bearer` hands a `dgrant:` token the owner's role AND
/// `FullAccess` together with the delegate's constraints, so the role check
/// cannot see the bounds. They bind only where a route NAMES its verb — a route
/// with no verb is a route with no enforcement — and none of these five named one
/// until now.
///
/// The grant here allows `announce` and nothing else, which is the shape codex
/// described: a delegate provisioned for one job reaching every other surface on
/// the node. All five must refuse, and each must say which contract refused it.
#[tokio::test]
async fn an_announce_only_delegate_reaches_no_contacts_or_chat_route() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;
    let delegated = mint_constrained_delegated_token(
        &engine,
        &owner_id,
        "wa-owner",
        CONTACT_KEY_ID,
        &["announce"],
    )
    .await;

    for (method, path, reason) in [
        (
            "GET",
            "/v1/contacts".to_string(),
            "contacts.delegation_denied",
        ),
        (
            "POST",
            "/v1/contacts".to_string(),
            "contacts.delegation_denied",
        ),
        ("POST", "/v1/chat".to_string(), "chat.delegation_denied"),
        (
            "GET",
            format!("/v1/chat/{community_id}/messages"),
            "chat.delegation_denied",
        ),
        (
            "POST",
            format!("/v1/chat/{community_id}/messages"),
            "chat.delegate_may_not_author",
        ),
    ] {
        let url = format!("{base}{path}");
        let req = match method {
            "GET" => client.get(&url),
            _ => client
                .post(&url)
                .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID, "body": "x" })),
        };
        let resp = req
            .bearer_auth(&delegated)
            .send()
            .await
            .expect("constrained delegate request");
        assert_eq!(
            resp.status(),
            403,
            "{method} {path} must refuse a delegate outside its allow-list"
        );
        let json: serde_json::Value = resp.json().await.expect("refusal json");
        assert_eq!(json["reason_id"], reason, "{method} {path}");
    }
}

/// A delegate granted the READ verb may read, and still may not SEND. The two
/// powers are separate verbs precisely so an owner can hand over one of them;
/// without this, "gate everything" and "gate the right things" look identical.
#[tokio::test]
async fn a_read_granted_delegate_reads_but_still_cannot_send() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;
    let delegated = mint_constrained_delegated_token(
        &engine,
        &owner_id,
        "wa-owner",
        CONTACT_KEY_ID,
        &["chat_read"],
    )
    .await;

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&delegated)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(
        resp.status(),
        200,
        "an explicitly read-granted delegate may read"
    );

    // `chat_author` is on the SERVER never-list, so even naming it in the
    // allow-list would not help — but here it simply is not granted.
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&delegated)
        .json(&serde_json::json!({ "body": "not mine to send" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 403);
    let json: serde_json::Value = resp.json().await.expect("refusal json");
    assert_eq!(json["reason_id"], "chat.delegate_may_not_author");
}

/// **A PEER WHOSE GRANT DOES NOT COVER `chat:` IS NOT A CONTACT.** The
/// accept-side mirror of the widening fix: `POST /v1/contacts` widens a narrow
/// grant on the SEND side, but the guard on `POST /v1/chat` accepted any consent
/// peer — so a key carrying only `capacity:`/`trace:` could have a room opened
/// with it and messages accepted locally, while `chat:` stayed ineligible to
/// replicate.
///
/// A one-way plane is worse than a closed one: it looks like a working
/// conversation from this side and arrives nowhere.
///
/// **This was `an_ordinarily_federated_peer_is_not_a_contact` and is not any
/// more.** The peering default now carries `chat:`, so an ordinary peering
/// produces a contact and the old name asserted something false. What survives
/// is the DOOR — the coverage guard and the refusal that names the missing
/// prefix — which still runs for any grant narrower than the contact set. What
/// the old name CLAIMED, that federation alone does not get you into a room, is
/// a different property on a different mechanism, and it is pinned next door in
/// [`an_ordinarily_federated_peer_is_still_not_in_the_room`].
#[tokio::test]
async fn a_peer_whose_grant_omits_chat_is_not_a_contact() {
    let (engine, base, owner, _owner_id, _h) = fixture().await;
    let node = node_key_id(&engine).await;
    // A standing peering grant without chat: — see `narrow_peering_prefixes`
    // for why this is not taken from the peering default.
    ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        CONTACT_KEY_ID,
        &narrow_peering_prefixes(),
    )
    .await
    .expect("federation peering grant");
    let client = reqwest::Client::new();

    // NOT listed: offering them would promise a conversation that never leaves.
    let listed = contacts_list(&client, &base, &owner).await;
    assert_eq!(
        listed["total"], 0,
        "a peer whose grant does not cover chat: is not a contact: {listed}"
    );

    // NOT accepted, and the refusal NAMES the missing prefix rather than saying
    // only "not a contact" — the operator needs to know it is a coverage gap and
    // not an unknown key.
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.expect("refusal body");
    assert!(body.contains("chat.not_a_contact"), "{body}");
    assert!(
        body.contains("chat:"),
        "the refusal must name the missing prefix: {body}"
    );

    // Adding them as a contact widens the grant, and BOTH doors then accept.
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200);
    let listed = contacts_list(&client, &base, &owner).await;
    assert_eq!(
        listed["total"], 1,
        "widening makes them a contact: {listed}"
    );
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 200, "the room opens once chat: is covered");
}

/// **WHAT ACTUALLY KEEPS AN ORDINARILY-FEDERATED PEER OUT OF A ROOM.**
///
/// While the peering default omitted `chat:`, the test above answered this by
/// accident: an ordinary peer's grant lacked the prefix, so the coverage guard
/// turned them away and nobody had to ask what would happen if it did not. The
/// default now carries `chat:` for every peer this node federates with, so that
/// accident is spent and the question is live and load-bearing.
///
/// **It was never the prefix.** `crate::peer`'s own doc says so and persist
/// agrees: the consent send-set is built from peer IDS alone, and the prefixes
/// gate only which rows `promote_consented_backlog` may PLACE — not the serve
/// wire. What withholds a room's rows from a non-member is edge's CC 5.2
/// audience gate, whose `community` arm serves a row only to a peer, or a
/// peer's principal, on the room's roster.
///
/// So this pins BOTH halves of that sentence, because either one going quiet
/// would make the other meaningless: the ordinarily-federated stranger IS in
/// the consent set AND their grant DOES cover `chat:` (so nothing on the
/// consent plane distinguishes them from a contact), and they are NOT on the
/// room's roster (so the audience gate is the only thing left standing).
///
/// # NAMED GAP — the gate itself is not exercised here
///
/// `FederationDirectoryReplicationBridge::audience_withholds` is private to
/// edge and needs a live replication bridge; this file drives the local HTTP
/// router against an in-memory substrate. What follows asserts the FACTS that
/// gate resolves, not the gate's use of them. A cross-node test that watches a
/// room row be withheld from a consented non-member is still owed, and until it
/// exists nothing in this repo fails if the audience gate stops consulting
/// membership. That is a real hole, and it got deeper the day the default
/// started granting `chat:` to every peer.
#[tokio::test]
async fn an_ordinarily_federated_peer_is_still_not_in_the_room() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let node = node_key_id(&engine).await;
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;

    // The room holds REAL content — a withholding test over an empty room
    // proves nothing, which is the same reason test 4 seeds a real message.
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "for the two of us" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200, "send: {:?}", resp.text().await);

    // Federate a stranger the ORDINARY way — today's real default, not a
    // narrowed one. This is the scenario the old test named and could no
    // longer produce.
    ciris_server::peer::emit_replication_consent(
        &engine,
        &node,
        STRANGER_A_KEY_ID,
        &ciris_server::peer::default_attestation_prefixes(),
    )
    .await
    .expect("ordinary federation peering grant");

    // HALF ONE — CONSENT DOES NOT HOLD THEM OUT. Both assertions are the
    // premise: if the stranger ever dropped out of the consent set, or the
    // default stopped covering chat:, the second half would be guarding a door
    // nobody walks through and would pass for the wrong reason.
    let peers = consent_subjects(&engine, &node).await;
    assert!(
        peers.iter().any(|p| p == STRANGER_A_KEY_ID),
        "an ordinarily-federated peer is in the folded consent set: {peers:?}"
    );
    assert!(
        live_grant_prefixes(&engine, &node, STRANGER_A_KEY_ID)
            .await
            .iter()
            .any(|p| p == ciris_edge::chat::CHAT_ATTESTATION_PREFIX),
        "and their grant COVERS chat: — the prefix is not what protects the room"
    );

    // HALF TWO — MEMBERSHIP DOES. The stranger is on no roster naming this
    // room, and the room's own active roster is exactly the pair. These are
    // the two reads the audience gate's `community` arm resolves.
    let directory = engine.federation_directory();
    let their_rooms = directory
        .list_communities_for_member_active(STRANGER_A_KEY_ID)
        .await
        .expect("list_communities_for_member_active");
    assert!(
        !their_rooms
            .iter()
            .any(|c| c.community_key_id == community_id),
        "a consented peer must not turn up on the roster of a room they were \
         never admitted to: {:?}",
        their_rooms
            .iter()
            .map(|c| &c.community_key_id)
            .collect::<Vec<_>>()
    );
    let mut members: Vec<String> = directory
        .active_community_members(&community_id)
        .await
        .expect("active_community_members")
        .into_iter()
        .map(|m| m.key_id)
        .collect();
    members.sort();
    let mut expected = vec![owner_id.key_id.clone(), CONTACT_KEY_ID.to_string()];
    expected.sort();
    assert_eq!(
        members, expected,
        "the room's roster is the pair and nobody else — federating with a \
         third party must not widen it"
    );
}

/// **THE BOUNDARY GATE — the pin, flipped.**
///
/// Its predecessor asserted this FAILED, and named exactly what would flip it.
/// This is that flip: the row a send writes is now attested and signed by the
/// same key, so persist's own `verify_row_hybrid_signature` — the gate the far
/// node runs on ingest — accepts it. Two live nodes observed the old row refused
/// with "Classical signature verification failed: Ed25519" while node-authored
/// rows landed beside it; this asserts the difference is gone.
///
/// It runs the REAL gate against the REAL directory rather than re-deriving what
/// verification ought to mean, so it cannot pass by agreeing with itself.
#[tokio::test]
async fn a_chat_message_verifies_at_the_persist_boundary() {
    use ciris_persist::federation::tier_ingest::verify_row_hybrid_signature;

    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "does this cross the wire?" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200);
    let sent: serde_json::Value = resp.json().await.expect("send json");
    let id = sent["attestation_id"].as_str().expect("attestation_id");

    // Under the OWNER's id, not the node's: since the signer-explicit send the
    // person attests their own words, so the row is authored where the person
    // is. Looking under the node here would find nothing — which is a stronger
    // statement of the same property, not a weaker one.
    let directory = engine.federation_directory();
    let row = directory
        .list_attestations_by(&owner_id.key_id)
        .await
        .expect("list_attestations_by")
        .into_iter()
        .find(|a| a.attestation_id == id)
        .expect("the stored message row");

    // Signer == attester: the property the far side's gate actually turns on.
    assert_eq!(row.attesting_key_id, owner_id.key_id);
    assert_eq!(
        row.scrub_key_id, row.attesting_key_id,
        "the split that made every cross-node ingest refuse must be gone"
    );
    verify_row_hybrid_signature(directory.as_ref(), &row)
        .await
        .expect("the far node's own ingest gate must accept this row");
}

/// **THE ATTRIBUTION HALF.** Delivery and authorship are two properties and the
/// pin above only holds one of them — a row could verify perfectly while having
/// quietly lost the human whose words it carries. That failure would be
/// invisible: everything green, every message signed, every message attributed
/// to a box.
///
/// So this asserts the other half, and asserts it where the claim now lives:
/// **in the signature**. The predecessor asserted the author rode as an
/// `on_behalf_of_key_id` envelope member and named the flip that would end that
/// — "if this ever equals the owner the signer-explicit upgrade has landed". It
/// has landed. The human signs their own words, so the envelope carries no
/// author CLAIM at all, and the projection reads the attester because the
/// attester IS the human. That is the same property held one rung higher: an
/// envelope member is producer-asserted and a signature is not.
#[tokio::test]
async fn the_message_names_its_human_author_inside_the_signed_envelope() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "my words, my signature" }))
        .send()
        .await
        .expect("POST message");
    assert_eq!(resp.status(), 200);
    let sent: serde_json::Value = resp.json().await.expect("send json");
    let id = sent["attestation_id"].as_str().expect("attestation_id");

    let node = node_key_id(&engine).await;
    let directory = engine.federation_directory();
    let row = directory
        .list_attestations_by(&owner_id.key_id)
        .await
        .expect("list_attestations_by")
        .into_iter()
        .find(|a| a.attestation_id == id)
        .expect("the stored message row");

    // THE SIGNATURE NAMES THE HUMAN. `verify_row_hybrid_signature` resolves the
    // attester's REGISTERED pubkeys and checks the bytes against them, so this
    // is the owner's own key or nothing — a relay that rewrote the author would
    // have to forge that signature, which is the point of moving the claim here
    // from an envelope member anyone in the room could have written.
    assert_eq!(
        row.attesting_key_id, owner_id.key_id,
        "the person attests their own words: {:?}",
        row.attestation_envelope
    );
    ciris_persist::federation::tier_ingest::verify_row_hybrid_signature(directory.as_ref(), &row)
        .await
        .expect("the human's own signature must verify against their registered key");
    assert!(
        row.attestation_envelope
            .get(contacts_chat::FIELD_ON_BEHALF_OF)
            .is_none(),
        "the author no longer rides as a producer-asserted envelope member — a row \
         carrying one again would mean the weaker mechanism came back: {:?}",
        row.attestation_envelope
    );

    // THE AUTHORITY THE NODE ACTS UNDER is still live and resolvable — not the
    // node's say-so. `is_steward_bound` is withdraws-aware, so this is the same
    // read that would stop being true the moment the owner revoked the binding,
    // and it is what the owner-gate on every route here rests on.
    assert_eq!(
        ciris_server::auth::ownership::is_steward_bound(&engine, &node).await,
        Some(owner_id.key_id.clone()),
        "a node serving its owner's chat must hold a LIVE owner-binding"
    );

    // AND THE PROJECTION AGREES: the card names the human on both fields.
    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    let list: serde_json::Value = resp.json().await.expect("messages json");
    let m = &list["messages"][0];
    assert_eq!(m["author"], owner_id.key_id, "author is the human: {m}");
    assert_eq!(
        m["attesting_key_id"],
        serde_json::json!(owner_id.key_id),
        "and so is the attester — one key, not a box speaking for a person"
    );
    assert_eq!(
        m["mine"], true,
        "`mine` follows the author, not the attester"
    );
}

// ─── The gates ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn every_route_refuses_without_an_owner_session() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;
    let observer = mint_session(&engine, "wa-observer", WaRole::Observer).await;

    for (method, path) in [
        ("GET", "/v1/contacts".to_string()),
        ("POST", "/v1/contacts".to_string()),
        ("POST", "/v1/chat".to_string()),
        ("GET", format!("/v1/chat/{community_id}/messages")),
        ("POST", format!("/v1/chat/{community_id}/messages")),
    ] {
        let url = format!("{base}{path}");
        let build = |c: &reqwest::Client| match method {
            "GET" => c.get(&url),
            _ => c
                .post(&url)
                .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID, "body": "x" })),
        };
        // No bearer at all.
        let resp = build(&client).send().await.expect("no-session request");
        assert_eq!(resp.status(), 401, "{method} {path} without a session");
        let json: serde_json::Value = resp.json().await.expect("refusal json");
        assert_eq!(json["reason_id"], "auth.owner_gate.missing_bearer");

        // A real session that is not the owner.
        let resp = build(&client)
            .bearer_auth(&observer)
            .send()
            .await
            .expect("observer request");
        assert_eq!(resp.status(), 403, "{method} {path} as a non-owner");
        let json: serde_json::Value = resp.json().await.expect("refusal json");
        assert_eq!(json["reason_id"], "auth.owner_gate.not_owner");
    }
}

/// **Two concurrent `POST /v1/chat` for the same pair both succeed** — the
/// advertised idempotency must hold exactly on the inputs where it matters:
/// a double tap, a client retry, two devices. Both requests can observe
/// `lookup_community == None` before either insert lands; the loser hits the
/// primary-key conflict, and before the race arm it surfaced that as a 500 for
/// a room that EXISTS.
///
/// The race is scheduler-dependent, so this is a PROPERTY test: many rounds of
/// truly concurrent pairs on fresh state, asserting the contract — never a
/// 5xx, both bodies name the same convergent room, and at most one arrival
/// claims `freshly_created`. Rounds where the race does not interleave pass
/// trivially; a round where it does would have failed before the fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_chat_creation_is_an_idempotent_success() {
    for round in 0..12 {
        let (_engine, base, owner, _owner_id, _h) = fixture().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/v1/contacts"))
            .bearer_auth(&owner)
            .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
            .send()
            .await
            .expect("POST /v1/contacts");
        assert_eq!(resp.status(), 200, "round {round}: add contact");

        let post = |c: reqwest::Client, b: String, o: String| async move {
            c.post(format!("{b}/v1/chat"))
                .bearer_auth(&o)
                .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
                .send()
                .await
                .expect("POST /v1/chat")
        };
        let (a, b) = tokio::join!(
            post(client.clone(), base.clone(), owner.clone()),
            post(client.clone(), base.clone(), owner.clone())
        );
        let (sa, sb) = (a.status(), b.status());
        let ja: serde_json::Value = a.json().await.expect("json a");
        let jb: serde_json::Value = b.json().await.expect("json b");
        assert!(
            sa == 200 && sb == 200,
            "round {round}: a concurrent chat creation must be an idempotent \
             success, got {sa}/{sb}: {ja} / {jb}"
        );
        assert_eq!(ja["community_id"], jb["community_id"], "round {round}");
        // Under persist v38.2.0 an IDENTICAL re-put is an Ok NO-OP (the typed
        // Conflict is reserved for a DIFFERING roster — a fork signal), so two
        // concurrent creators of the same deterministic room are
        // indistinguishable and BOTH may honestly report freshly_created. The
        // pre-v38.2 assertion "at most one freshly_created" pinned the old
        // door's shape. What must hold in every world: one room, one roster,
        // and the no-op preserved the first-accepted authority signature —
        // there is exactly ONE stored row and its member set is the pair.
        assert_eq!(
            ja["member_key_ids"], jb["member_key_ids"],
            "round {round}: both arrivals must see the same roster"
        );
    }
}

// ─── The author claim is validated, not trusted ─────────────────────────────

/// Seed a NODE-role key: a steward-binding's target must be a node —
/// `delegates_to` onto a user-role key is guardianship-only (CC 3.2, the
/// refusal this test first hit), so the contact's node must carry
/// `identity_type::NODE` exactly as a real node registration does.
async fn seed_node_key(engine: &Engine, key_id: &str, ed_seed: u8, pqc_seed: u8) {
    let ed = SigningKey::from_bytes(&[ed_seed; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[pqc_seed; 32], format!("{key_id}-pqc"))
        .expect("ML-DSA-65 seed");
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize registration");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode(ed.verifying_key().to_bytes()),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(mldsa.public_key().await.expect("ml-dsa pk"))),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::NODE.into(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .unwrap_or_else(|e| panic!("seed node key {key_id}: {e}"));
}

/// Build a signer for `CONTACT_KEY_ID` from the same seeds the fixture
/// registered its pubkeys under, so a binding it emits verifies as the real
/// contact's act.
fn contact_signer() -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xB1; 32], format!("{CONTACT_KEY_ID}-pqc"))
            .expect("contact ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xB0; 32]),
        CONTACT_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{CONTACT_KEY_ID}-pqc")),
    )
}

/// **A forged `on_behalf_of_key_id` cannot render as the local owner's words**
/// (codex, contacts_chat.rs:1303).
///
/// The envelope member is producer-asserted: any node inside the transcript's
/// scan set can sign a valid community row whose envelope claims OUR owner as
/// author. The projection now honors the claim only when the attesting node's
/// LIVE owner-binding names the claimed member. Three assertions, one run:
/// the forgery projects the WIRE TRUTH (the forging node) and never `mine`;
/// the same forger's row claiming its OWN bound member projects that member
/// (the positive case that makes the far side's legitimate messages work);
/// and the owner's genuine message still projects the owner.
#[tokio::test]
async fn a_forged_author_claim_projects_the_attester_never_the_owner() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _contact_material) =
        open_chat(&client, &base, &owner, &engine, &owner_id).await;

    // A genuine message from the owner, as a control. Its id is kept because the
    // sealed body cannot be picked out of the transcript by eye.
    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "genuine" }))
        .send()
        .await
        .expect("send genuine");
    let status = resp.status();
    let body = resp.text().await.expect("send genuine body");
    assert_eq!(status, 200, "send genuine: {body}");
    let genuine_id = serde_json::from_str::<serde_json::Value>(&body).expect("send json")
        ["attestation_id"]
        .as_str()
        .expect("attestation_id")
        .to_string();

    // The contact's NODE no longer figures in this test. It used to: the read
    // path scanned node keys and walked each node's owner-binding to decide
    // whether a claimed author was backed, so the attack surface was a node with
    // a real binding. Both the scan and the walk are gone — a row is read only if
    // a ROSTER MEMBER attested it, and the attester is the author — so the only
    // forgery that can still reach a reader is a member's own.

    // THE FORGERY, in the shape that can still reach a reader: a row the CONTACT
    // really signed, claiming our owner wrote it.
    //
    // The old shape — a row attested by the contact's NODE — cannot be read at
    // all now, and that is the stronger property: `collect_messages` is anchored
    // on the ROSTER, so a row no member attested is never projected. Two things
    // that used to stand between such a row and the reader are gone with it: the
    // `node_key_ids` scan, and the owner-binding walk that re-derived trust in a
    // producer-asserted `on_behalf_of_key_id`. From edge v20.0.0 the author IS
    // the attester, established by the signature instead of by us.
    let forged =
        seed_message_attested_by(&engine, &contact_signer(), &owner_id.key_id, &community_id).await;
    // The same member's legitimate row: it claims itself.
    let legit =
        seed_message_attested_by(&engine, &contact_signer(), CONTACT_KEY_ID, &community_id).await;

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.expect("messages json");
    let msgs = json["messages"].as_array().expect("messages array");

    let find = |id: &str| {
        msgs.iter()
            .find(|m| m["attestation_id"] == id)
            .unwrap_or_else(|| panic!("row {id} missing from transcript"))
    };
    let f = find(&forged);
    assert_eq!(
        f["author"], CONTACT_KEY_ID,
        "a claim the signature does not back must project the WIRE TRUTH — the \
         attester — not the claim: {f}"
    );
    assert_eq!(
        f["mine"], false,
        "a forged claim must never render as the local owner's own words: {f}"
    );
    let l = find(&legit);
    assert_eq!(
        l["author"], CONTACT_KEY_ID,
        "a member claiming ITSELF is the legitimate far-side shape and must \
         project the member: {l}"
    );
    let genuine = find(&genuine_id);
    assert_eq!(genuine["author"], owner_id.key_id);
    assert_eq!(genuine["mine"], true);
}

/// A message row attested by `node`, claiming `author` — the wire shape a
/// FOREIGN node's row arrives in (raw put, community scope, no promote step:
/// a replicated row lands already at its tier).
async fn seed_message_attested_by(
    engine: &Engine,
    attester: &LocalSigner,
    author: &str,
    community_id: &str,
) -> String {
    let envelope = serde_json::json!({
        (paths::DIMENSION): contacts_chat::CHAT_MESSAGE_DIMENSION,
        // EDGE'S NAMES, not ours. `ChatMessage::from_row` asks `room_of`, which
        // reads `FIELD_COMMUNITY_ID` — and that is `community_key_id`, the
        // canonical cohort-member spelling. Hand-writing `community_id` here made
        // the row invisible to the reader rather than wrong-looking: `from_row`
        // returned `None` and the transcript simply did not contain it.
        (contacts_chat::FIELD_COMMUNITY_ID): community_id,
        (contacts_chat::FIELD_ON_BEHALF_OF): author,
        (contacts_chat::FIELD_BODY): format!("as {author}"),
        (contacts_chat::FIELD_CONTENT_TYPE): "text/plain",
        "score": 1.0,
    });
    // A REPLICATED ROW LANDS AT ITS TIER. There is no crossing here and there
    // must not be: `enter_mesh`/`widen_audience` are how a row this node authored
    // LEAVES, and v39 is explicit that this node cannot place another key's
    // claim. The far side signed its own row in; we emit it through the one door
    // under the attester's key, at the tier it arrives at.
    ciris_server::attest::emit(
        engine,
        ciris_server::attest::KeySigner::Local(attester),
        ciris_server::attest::Spec::new(
            attestation_type::SCORES,
            cohort_scope::COMMUNITY,
            envelope,
        )
        .about(attester.key_id()),
    )
    .await
    .expect("emit foreign-shaped chat message")
}

/// **The transcript's schema is the one a CHANNEL needs, not the one a pair does.**
///
/// Chat rooms and agent conversations are one client surface, so an entry has to
/// carry two independent facts: what KIND of entry it is (viewer-independent),
/// and who wrote it (with the viewer-relative reading marked as derived). A flat
/// `self | other_human | my_agent | ...` role cannot express a room with fifty
/// people in it, and gives one row two different names depending on who is
/// looking — in a transcript that is byte-identical for every member.
#[tokio::test]
async fn every_entry_carries_its_kind_and_its_author_on_separate_axes() {
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let (community_id, _m) = open_chat(&client, &base, &owner, &engine, &owner_id).await;

    let resp = client
        .post(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "body": "on two axes" }))
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );

    let json: serde_json::Value = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages")
        .json()
        .await
        .expect("messages json");
    let m = &json["messages"].as_array().expect("messages")[0];

    assert_eq!(
        m["kind"], "message",
        "a person speaking is a `message`: {m}"
    );
    assert_eq!(
        m["author_kind"], "person",
        "the author is a HUMAN and the entry must say so — a channel draws an \
         agent differently from the person who owns it, and cannot if the only \
         signal is the key: {m}"
    );
    assert_eq!(
        m["relation"], "self",
        "the viewer-relative reading, derived from the author: {m}"
    );
    assert_eq!(
        m["mine"], true,
        "`mine` is retained and must agree with `relation` — two fields that can \
         disagree are worse than one: {m}"
    );
    assert!(
        m["message_id"].is_null(),
        "a spoken message has no localization key; only system/error notes do: {m}"
    );
}

/// **A room that has not finished starting says so IN THE TRANSCRIPT.**
///
/// The handshake is not an error and must not arrive as one: a pair room is
/// end-to-end encrypted, so it spends real time waiting for the other side's
/// KeyPackage to replicate. That is a thing the conversation can say. It used to
/// be `503 chat.room_not_keyed_yet` — one sentence for four situations, on a
/// surface with no way to name which, leaving every client to invent wording for
/// a state the server knows exactly.
#[tokio::test]
async fn an_unstarted_room_returns_a_system_note_not_an_error() {
    let (_engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    // A contact who has NEVER opened the room, so no KeyPackage can exist.
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200, "add the contact");
    let community_id =
        ciris_server::contacts_chat::pair_community_key_id(&owner_id.key_id, CONTACT_KEY_ID);
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 200, "open the room");

    let resp = client
        .get(format!("{base}/v1/chat/{community_id}/messages"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET messages");
    assert_eq!(
        resp.status(),
        200,
        "a conversation that has not finished starting is not a failure"
    );
    let json: serde_json::Value = resp.json().await.expect("messages json");
    let msgs = json["messages"].as_array().expect("messages array");
    assert_eq!(
        msgs.len(),
        1,
        "the system note is IN the transcript: {json}"
    );
    let note = &msgs[0];
    assert_eq!(note["kind"], "system", "{note}");
    assert_eq!(
        note["message_id"], "chat.state.awaiting_peer",
        "we CREATED this room, so we are waiting on the peer's KeyPackage — and \
         the id must name WHICH note, since `system` is not something a user \
         reads: {note}"
    );
    assert!(
        note["body"].as_str().is_some_and(|b| !b.is_empty()),
        "the English fallback rides along, or a client whose bundle has not \
         caught up renders a blank line: {note}"
    );
    assert_eq!(
        json["total"], 0,
        "`total` counts what people SAID — counting the room's own note would \
         make an unstarted conversation report a message: {json}"
    );
    assert_eq!(
        json["converges_on_its_own"], true,
        "the client's cue to wait rather than offer a retry button: {json}"
    );
}

/// **A pre-planted room under the derived pair id is a conflict, not a chat**
/// (codex, contacts_chat.rs:702).
///
/// The pair id is derivable by anyone, so a peer can replicate a community
/// under it carrying the pair PLUS a stowaway. The front door now applies the
/// same sorted-member equality the insert-race arm uses — and the refusal
/// leaks nothing about who is on the poisoned roster.
#[tokio::test]
async fn a_poisoned_roster_under_the_pair_id_is_refused() {
    use ciris_persist::federation::types::{Community, CommunityMember};
    let (engine, base, owner, owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200);

    let community_id = pair_community_key_id(&owner_id.key_id, CONTACT_KEY_ID);
    let now = chrono::Utc::now();
    engine
        .put_community_self_signed(Community {
            community_key_id: community_id.clone(),
            community_name: "poisoned".to_string(),
            members: [owner_id.key_id.as_str(), CONTACT_KEY_ID, STRANGER_A_KEY_ID]
                .iter()
                .map(|k| CommunityMember {
                    key_id: (*k).to_string(),
                    joined_at: now,
                    role: None,
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "unanimous".to_string(),
            policy_blob: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("pre-plant the poisoned room");

    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 409, "a wrong-roster room must refuse");
    let body = resp.text().await.expect("refusal body");
    let json: serde_json::Value = serde_json::from_str(&body).expect("refusal json");
    assert_eq!(json["reason_id"], "chat.community_shape_conflict");
    assert!(
        !body.contains(STRANGER_A_KEY_ID),
        "the refusal must not leak who is on the poisoned roster: {body}"
    );
}

/// **Both chat WRITE handlers call the declared-conformance gate** (codex,
/// contacts_chat.rs:633). ChatCreate/ChatAuthor declare [Producer, Substrate]
/// in `conformance::required_profiles`, and a declaration is only real if
/// something REFUSES when it is absent — the profiles were declared (the
/// exhaustive match forced it) while neither write handler enforced them, so a
/// node whose config omitted CCP/CCS still authored federation-wire rows.
/// Source-scoped to each handler's body, the owner_signer_capsule lesson: a
/// whole-file grep also matches the comment that explains the rule.
#[test]
fn both_chat_write_handlers_enforce_declared_conformance() {
    let src = include_str!("../src/contacts_chat.rs");
    for handler in ["async fn start_chat(", "async fn send_message("] {
        let start = src
            .find(handler)
            .unwrap_or_else(|| panic!("{handler} must exist"));
        let body = &src[start..(start + 6000).min(src.len())];
        assert!(
            body.contains("conformance::require_op"),
            "{handler} no longer calls the declared-conformance gate — a node \
             whose config:node.conformance_profiles does not claim \
             [Producer, Substrate] would author federation-wire chat rows it \
             explicitly does not claim the roles for"
        );
    }
}

/// **CIRISServer#472 — a claimed contact's grant names their bound NODE**, the
/// only subject the wire can route. The person stays the CONTACT (the listing
/// resolves the node-subject back through the owner-binding, once), and the
/// chat guard reads coverage through the same resolution — one door, both
/// directions.
#[tokio::test]
async fn a_claimed_contacts_grant_names_their_bound_node() {
    let (engine, base, owner, _owner_id, _h) = fixture().await;
    let client = reqwest::Client::new();

    // Claim the contact: a NODE-role key bound by the contact's own live
    // owner-binding — the same fixture shape the forged-author test uses.
    const CONTACT_NODE: &str = "contact-node-1";
    seed_node_key(&engine, CONTACT_NODE, 0xE0, 0xE1).await;
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ciris_server::auth::ownership::emit_steward_binding(
        &engine,
        &contact_signer(),
        CONTACT_NODE,
        &scopes,
    )
    .await
    .expect("bind contact -> their node");

    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/contacts");
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    // THE ROUTABLE FACT: the chat:-covering grant's live subject is the NODE.
    let node = node_key_id(&engine).await;
    let node_prefixes = ciris_server::peer::live_grant_prefixes(&engine, &node, CONTACT_NODE)
        .await
        .expect("read node-subject grant");
    let node_prefixes = node_prefixes.expect("the grant must name the contact's bound node");
    assert!(
        node_prefixes.iter().any(|p| p == "chat:"),
        "the NODE-subject grant must cover chat: — that is what makes messages \
         eligible to leave this node: {node_prefixes:?}"
    );
    // And the PERSON carries no fresh person-subject grant on this path (the
    // fallback is for unclaimed contacts only).
    let person_prefixes = ciris_server::peer::live_grant_prefixes(&engine, &node, CONTACT_KEY_ID)
        .await
        .expect("read person-subject grant");
    assert!(
        person_prefixes.is_none(),
        "a claimed contact must not get the unroutable person-subject grant: \
         {person_prefixes:?}"
    );

    // THE HUMAN FACT: the listing shows the PERSON, exactly once — the
    // node-subject resolves back through owner_of.
    let resp = client
        .get(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .send()
        .await
        .expect("GET /v1/contacts");
    let list: serde_json::Value = resp.json().await.expect("contacts json");
    assert_eq!(list["total"], 1, "one person, one contact: {list}");
    assert_eq!(list["contacts"][0]["key_id"], CONTACT_KEY_ID);

    // And the chat door opens through the SAME resolution.
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .expect("POST /v1/chat");
    assert_eq!(resp.status(), 200, "start chat: {:?}", resp.text().await);
}
