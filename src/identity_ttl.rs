//! **A stated end for a harness node's own identity rows** (0.5.247; steward
//! ruling 2026-11-13, the canonical's store floor).
//!
//! Every CI or QA node that reaches the canonical leaves its key record, its
//! signed identity occurrence and its owner's binding there for good: 9,518
//! keys on 2026-11-13 against ~1,350 announced nodes, growing with every run.
//! The constitution already has the cure. A key record, an occurrence and an
//! owner-binding honour their own stated end (`valid_until` /
//! `expires_at`), so a row signed with a short end leaves nothing live behind
//! it at any node.
//!
//! `CIRIS_NODE_IDENTITY_TTL_S=<seconds>` gives this process's identity rows
//! that end: the node key, the agent key, the owner's fed-ID key, the node's
//! signed self occurrence and the owner-binding. Unset (production), nothing
//! changes. Every such row is signed exactly as before, with no end.
//!
//! The end is fixed once per process (`now + ttl` at first use) and signed
//! into each row's envelope, never added beside it. A restart inside a run
//! re-derives a later end, but the rows it would re-sign are already held and
//! persist answers their re-registration as the idempotent conflict it is, so
//! the first end stands.

use std::sync::OnceLock;

use chrono::{DateTime, SecondsFormat, Utc};

/// The variable a harness sets on the node it launches.
pub const ENV: &str = "CIRIS_NODE_IDENTITY_TTL_S";

/// The shortest end accepted: a run needs its rows live while it runs.
const MIN_SECS: u64 = 600;

fn parse(raw: Option<&str>, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let Ok(secs) = raw.parse::<u64>() else {
        tracing::warn!(
            value = raw,
            "{ENV} is not a whole number of seconds; identity rows get no end"
        );
        return None;
    };
    let secs = secs.max(MIN_SECS);
    let secs = i64::try_from(secs).ok()?;
    // Millisecond-exact, as every signed instant (persist `same_instant_ms`).
    let end = now + chrono::Duration::seconds(secs);
    let mut ms = end.timestamp_millis();
    // NEVER a whole second. verify v22.2.0's `Validity::checked` re-formats the
    // signed `valid_until` with `SecondsFormat::AutoSi`, which drops a zero
    // fraction ("…:15Z"), and persist refuses anything but the CC 2.6.2
    // `.sssZ` form (CIRISPersist#659): about one boot in a thousand failed
    // `self-register` (CIRISClient five-platform run 44867953009, 2026-11-21).
    // One millisecond later keeps the instant ms-exact and the text `.001Z`.
    if ms.rem_euclid(1000) == 0 {
        ms += 1;
    }
    DateTime::from_timestamp_millis(ms)
}

/// This process's identity end, when a harness asked for one.
#[must_use]
pub fn valid_until() -> Option<DateTime<Utc>> {
    static UNTIL: OnceLock<Option<DateTime<Utc>>> = OnceLock::new();
    *UNTIL.get_or_init(|| {
        let end = parse(std::env::var(ENV).ok().as_deref(), Utc::now());
        if let Some(end) = end {
            tracing::warn!(
                valid_until = %end,
                "{ENV} is set: this node's own identity rows carry a stated end and lapse \
                 everywhere after it. For harness and CI nodes only."
            );
        }
        end
    })
}

/// [`valid_until`] as the RFC 3339 string a signed envelope carries.
#[must_use]
pub fn valid_until_str() -> Option<String> {
    valid_until().map(|t| t.to_rfc3339_opts(SecondsFormat::Millis, true))
}

#[cfg(test)]
mod whole_second_tests {
    use super::*;

    #[test]
    fn an_end_on_a_whole_second_moves_one_millisecond() {
        // A start whose end lands exactly on a second (the 2026-11-21 failure).
        let now = DateTime::parse_from_rfc3339("2026-11-21T06:26:15.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = parse(Some("10800"), now).expect("an end");
        assert_eq!(end.timestamp_millis().rem_euclid(1000), 1);
        let text = end.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        assert_eq!(
            text, "2026-11-21T09:26:15.001Z",
            "AutoSi keeps the fraction"
        );
        // Any other end is left as it is.
        let now = DateTime::parse_from_rfc3339("2026-11-21T05:43:26.523Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            parse(Some("10800"), now)
                .unwrap()
                .timestamp_millis()
                .rem_euclid(1000),
            523
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-13T12:00:00.123Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn unset_or_blank_or_garbage_means_no_end() {
        assert_eq!(parse(None, at()), None);
        assert_eq!(parse(Some(""), at()), None);
        assert_eq!(parse(Some("a day"), at()), None);
    }

    #[test]
    fn an_end_is_now_plus_the_ttl_to_the_millisecond() {
        let end = parse(Some("86400"), at()).expect("an end");
        assert_eq!(end, at() + chrono::Duration::days(1));
        assert_eq!(end.timestamp_subsec_nanos() % 1_000_000, 0);
    }

    #[test]
    fn a_ttl_shorter_than_a_run_is_raised_to_the_floor() {
        let end = parse(Some("5"), at()).expect("an end");
        assert_eq!(end, at() + chrono::Duration::seconds(600));
    }
}
