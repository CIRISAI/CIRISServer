//! `ciris-server accord sign-bytes` — an accord holder signs a file's exact bytes.
//!
//! The agent's accord manifest has to be signed by an accord holder, and with the
//! 2025 root retired A1 is the only signer left. Every other holder-signing path in
//! this crate signs a fixed shape (an invocation, a family cosign, a final-genesis
//! plan, a canonical add). This one signs whatever bytes it is given, so its guards
//! carry the weight:
//!
//! 1. **Only a baked accord holder.** The key id must name a record in persist's
//!    effective accord-holder roster; anything else is refused before the token is
//!    touched. The signatures are checked against THAT record, not against keys the
//!    token reports about itself.
//! 2. **The right token before the PIN.** The existing PIV preflight refuses a
//!    YubiKey it can positively identify as another holder, so no PIN attempt is
//!    spent on the wrong one.
//! 3. **Bound hybrid, CC 5.3.2.4.3.1.** Ed25519 over the bytes, then ML-DSA-65 over
//!    the bytes ‖ the Ed25519 signature — `HardwareRootedIdentity::sign_bound`, the
//!    same call the invocation and family-cosign paths use.
//! 4. **Self-verify before output.** Both halves are verified with
//!    `substrate::verify_bound_hybrid` against the baked record. A failure prints
//!    nothing on stdout and exits non-zero.
//!
//! The bytes are signed exactly as read: no canonicalisation, no newline handling.
//! stdout carries the one JSON object and nothing else (`main` skips tracing setup
//! for this verb, because the tracing sink writes to stdout); prompts and errors go
//! to stderr. Nothing is written to disk. The ML-DSA seed is unwrapped in memory by
//! `UsbWrappedMlDsa65Signer` and never leaves the process.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const USAGE: &str =
    "usage: ciris-server accord sign-bytes --key-id <holder> --usb <dir> --in <file> \
     [--pin-stdin] [--piv-slot 9c] [--module <libykcs11>]";

/// Parsed flags.
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    key_id: String,
    usb: String,
    input: String,
    pin_stdin: bool,
    piv_slot: Option<String>,
    module: Option<String>,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Args> {
    let mut a = Args::default();
    while let Some(arg) = args.next() {
        let mut val = |name: &str| args.next().with_context(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--key-id" => a.key_id = val("--key-id")?,
            "--usb" => a.usb = val("--usb")?,
            "--in" => a.input = val("--in")?,
            "--pin-stdin" => a.pin_stdin = true,
            "--piv-slot" => a.piv_slot = Some(val("--piv-slot")?),
            "--module" => a.module = Some(val("--module")?),
            other => bail!("unknown accord-sign-bytes arg: {other}\n{USAGE}"),
        }
    }
    if a.key_id.is_empty() || a.usb.is_empty() || a.input.is_empty() {
        bail!("--key-id, --usb and --in are all required\n{USAGE}");
    }
    Ok(a)
}

/// The baked record's two public keys for `key_id`, or a refusal.
fn holder_pubkeys(key_id: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let roster = ciris_persist::federation::genesis::effective_accord_holder_records();
    let rec = roster
        .iter()
        .find(|h| h.record.key_id == key_id)
        .map(|h| &h.record)
        .ok_or_else(|| {
            let seats: Vec<&str> = roster.iter().map(|h| h.record.key_id.as_str()).collect();
            anyhow!(
                "'{key_id}' is not a baked accord holder (holders: {}); refusing before the \
                 token is touched",
                seats.join(", ")
            )
        })?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let ed = b64
        .decode(rec.pubkey_ed25519_base64.trim())
        .context("baked Ed25519 key is not base64")?;
    let pq = rec
        .pubkey_ml_dsa_65_base64
        .as_deref()
        .ok_or_else(|| anyhow!("baked record for '{key_id}' has no ML-DSA-65 key; refusing"))?;
    let pq = b64
        .decode(pq.trim())
        .context("baked ML-DSA-65 key is not base64")?;
    Ok((ed, pq))
}

/// Verify a bound hybrid signature over `bytes` against the two public keys.
fn verify(bytes: &[u8], ed_b64: &str, pq_b64: &str, ed_pub: &[u8], pq_pub: &[u8]) -> Result<()> {
    use ciris_verify_core::substrate::preimage::{verify_bound_hybrid, BoundHybridSig};
    let b64 = base64::engine::general_purpose::STANDARD;
    let ed = b64
        .decode(ed_b64)
        .context("Ed25519 signature is not base64")?;
    let pq = b64
        .decode(pq_b64)
        .context("ML-DSA-65 signature is not base64")?;
    let sig = BoundHybridSig {
        ed25519: &ed,
        mldsa65: Some(&pq),
    };
    verify_bound_hybrid(bytes, &sig, ed_pub, pq_pub)
        .map_err(|e| anyhow!("the signature does not verify against the baked record: {e:?}"))
}

/// The output object. `sha256` is over the exact input bytes.
fn output(key_id: &str, bytes: &[u8], ed_b64: &str, pq_b64: &str) -> serde_json::Value {
    serde_json::json!({
        "key_id": key_id,
        "ed25519_signature_base64": ed_b64,
        "mldsa65_signature_base64": pq_b64,
        "sha256": hex::encode(Sha256::digest(bytes)),
    })
}

/// Read the PIN: one line from stdin with `--pin-stdin`, else a no-echo prompt on
/// the controlling terminal. Nothing is printed to stdout either way.
fn read_pin(from_stdin: bool) -> Result<String> {
    use std::io::{BufRead, Write};
    let mut line = String::new();
    if from_stdin {
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("read the PIN from stdin")?;
    } else {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context("no terminal to prompt for the PIN on; pass --pin-stdin")?;
        let stty = |arg: &str| {
            std::process::Command::new("stty")
                .arg(arg)
                .stdin(tty.try_clone().expect("tty handle"))
                .status()
        };
        let _ = stty("-echo");
        eprint!("YubiKey PIV PIN: ");
        let _ = std::io::stderr().flush();
        let res = std::io::BufReader::new(&tty).read_line(&mut line);
        let _ = stty("echo");
        eprintln!();
        res.context("read the PIN from the terminal")?;
    }
    let pin = line.trim_end_matches(['\r', '\n']).to_string();
    line.zeroize();
    if pin.is_empty() {
        bail!("empty PIN");
    }
    Ok(pin)
}

/// The verb. Prints the JSON object on success; returns Err (stdout untouched) on
/// any failure, which `main` turns into a non-zero exit.
pub async fn run_cli(args: impl Iterator<Item = String>) -> Result<()> {
    let a = parse(args)?;
    let (ed_pub, pq_pub) = holder_pubkeys(&a.key_id)?;
    let bytes = std::fs::read(&a.input).with_context(|| format!("read {}", a.input))?;
    let mut pin = read_pin(a.pin_stdin)?;
    let signed = sign(&a, &bytes, Some(pin.clone())).await;
    pin.zeroize();
    let (ed_b64, pq_b64) = signed?;
    verify(&bytes, &ed_b64, &pq_b64, &ed_pub, &pq_pub)?;
    println!("{}", output(&a.key_id, &bytes, &ed_b64, &pq_b64));
    eprintln!(
        "signed {} bytes as {} (sha256 {}); both halves verified against the baked record",
        bytes.len(),
        a.key_id,
        hex::encode(Sha256::digest(&bytes))
    );
    Ok(())
}

#[cfg(feature = "pkcs11")]
async fn sign(a: &Args, bytes: &[u8], user_pin: Option<String>) -> Result<(String, String)> {
    use ciris_verify_core::self_at_login::SelfSigner;
    let pkcs11 = crate::accord_provision::ProvisionPkcs11 {
        user_pin,
        piv_slot: a.piv_slot.clone(),
        module_path: a.module.clone(),
    };
    eprintln!(
        "opening {}'s YubiKey and USB key; touch the YubiKey when it blinks",
        a.key_id
    );
    let identity = crate::accord_provision::open_holder_identity(&a.key_id, &a.usb, &pkcs11)
        .await
        .map_err(|(_, msg)| anyhow!(msg))?;
    if identity.key_id() != a.key_id {
        bail!(
            "opened identity '{}' is not '{}'",
            identity.key_id(),
            a.key_id
        );
    }
    identity
        .sign_bound(bytes)
        .await
        .map_err(|e| anyhow!("hardware sign failed (touch timed out?): {e}"))
}

#[cfg(not(feature = "pkcs11"))]
async fn sign(_a: &Args, _bytes: &[u8], _pin: Option<String>) -> Result<(String, String)> {
    bail!("accord sign-bytes needs the `pkcs11` feature (on by default); rebuild with it")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &[&str]) -> impl Iterator<Item = String> {
        s.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn parse_requires_key_usb_and_input() {
        assert!(parse(argv(&["--key-id", "A1", "--usb", "/u"])).is_err());
        assert!(parse(argv(&[
            "--key-id", "A1", "--usb", "/u", "--in", "m", "--bogus"
        ]))
        .is_err());
        let a = parse(argv(&[
            "--key-id",
            "A1",
            "--usb",
            "/u",
            "--in",
            "m",
            "--pin-stdin",
            "--piv-slot",
            "9a",
        ]))
        .unwrap();
        assert_eq!(a.key_id, "A1");
        assert!(a.pin_stdin);
        assert_eq!(a.piv_slot.as_deref(), Some("9a"));
    }

    #[test]
    fn a_key_that_is_not_a_baked_holder_is_refused() {
        let e = holder_pubkeys("not-a-holder").unwrap_err().to_string();
        assert!(e.contains("not a baked accord holder"), "{e}");
        let (ed, pq) = holder_pubkeys("A1").expect("A1 is baked with both halves");
        assert_eq!(ed.len(), 32);
        assert_eq!(pq.len(), 1952);
    }

    /// The verify half accepts exactly the bound construction over the exact
    /// bytes, and refuses one changed byte or an unbound ML-DSA half.
    #[tokio::test]
    async fn verify_accepts_only_the_bound_signature_over_the_exact_bytes() {
        use ciris_verify_core::self_at_login::{HybridSigningIdentity, SelfSigner};
        let id = HybridSigningIdentity::generate("t").expect("software identity");
        let bytes = b"manifest bytes\n".to_vec();
        let (ed_b64, pq_b64) = id.sign_bound(&bytes).await.expect("sign");
        let ed_pub = id.ed25519_public_key().await.unwrap();
        let pq_pub = id.mldsa65_public_key().await.unwrap();
        verify(&bytes, &ed_b64, &pq_b64, &ed_pub, &pq_pub).expect("verifies");

        let mut changed = bytes.clone();
        changed.pop(); // the trailing newline is part of what was signed
        assert!(verify(&changed, &ed_b64, &pq_b64, &ed_pub, &pq_pub).is_err());

        let (_, other_pq) = id.sign_bound(b"something else").await.unwrap();
        assert!(verify(&bytes, &ed_b64, &other_pq, &ed_pub, &pq_pub).is_err());

        let out = output("A1", &bytes, &ed_b64, &pq_b64);
        assert_eq!(out["sha256"], hex::encode(Sha256::digest(&bytes)));
        assert_eq!(out.as_object().unwrap().len(), 4);
    }
}
