//! **What this node can tell about its own host at boot** — the one place the
//! install path, the host kind and the server tier are read (Eric, 2026-11-10).
//!
//! Three answers, each from signals present before any wizard has run:
//!
//! - [`Installer`]: which product set the node up. A node an agent split out
//!   is `cirisagent`; a node booted bare (the wheel, the binary, the desktop
//!   app's own node) is `cirisserver`.
//! - [`host_kind`]: a coarse word for the host. A CIRISManager agent names
//!   itself by its agent id; otherwise `android`, `ios`, `docker`, `desktop`
//!   or `server`.
//! - [`ServerTier`]: whether this node is server tier. That means enough
//!   storage (a data disk of at least [`SERVER_TIER_MIN_DISK_BYTES`]) and not
//!   a personal install (not a desktop, a phone, or the desktop app's node).
//!   Server tier is a property of the host. It is NOT a blessing: the canonical
//!   is blessed (`infra:serve` through the accord), and an unblessed
//!   server-tier node is still expected to serve as a proxy and cache for
//!   federation-tier content.
//!
//! The words end up in a node key's alias (see
//! [`crate::key_convention::descriptive_node_alias`]), which is public in its
//! `key_id`. So none of them is personal: no hostname, no user name, no device
//! label. The wizard's device name stays a private, renamable label.

/// Which product set this node up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Installer {
    /// An agent's install split this node out (the agent key is the actor).
    CirisAgent,
    /// The node was booted bare: the wheel, the binary or the desktop app.
    CirisServer,
}

impl Installer {
    /// The word in the alias. One segment each, so the I3 guard (no bare
    /// `agent` or `user` segment in a node alias) holds.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::CirisAgent => "cirisagent",
            Self::CirisServer => "cirisserver",
        }
    }
}

/// An operator's override for [`host_kind`]: `CIRIS_NODE_HOST_KIND`.
pub const HOST_KIND_ENV: &str = "CIRIS_NODE_HOST_KIND";

/// Lower-case ASCII letters and digits only, at most 24 of them. `None` when
/// nothing is left, or when the result is a role word that would put a
/// cohabitation claim into a node alias.
#[must_use]
pub fn slug(raw: &str) -> Option<String> {
    let s: String = raw
        .chars()
        .flat_map(char::to_lowercase)
        .filter(char::is_ascii_alphanumeric)
        .take(24)
        .collect();
    match s.as_str() {
        "" | "agent" | "user" | "node" => None,
        _ => Some(s),
    }
}

fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

/// Is this process in a container? Docker, podman or Kubernetes.
#[must_use]
pub fn in_container() -> bool {
    std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
        || env_set("KUBERNETES_SERVICE_HOST")
}

/// Does this host look like a person's own desktop? A GUI OS, a Linux
/// session with a display, or the desktop app's node (its launcher sets
/// `CIRIS_DEVICE_CLASS=laptop`).
#[must_use]
pub fn is_desktop() -> bool {
    if std::env::var("CIRIS_DEVICE_CLASS")
        .map(|v| matches!(v.trim(), "laptop" | "desktop"))
        .unwrap_or(false)
    {
        return true;
    }
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        return true;
    }
    cfg!(target_os = "linux") && (env_set("DISPLAY") || env_set("WAYLAND_DISPLAY"))
}

/// The coarse host word, first match wins:
///
/// 1. `CIRIS_NODE_HOST_KIND`, if it slugs to something;
/// 2. a CIRISManager agent ([`crate::deployment::is_managed`]): its
///    `CIRIS_AGENT_ID`, else `docker`;
/// 3. `android` / `ios`, by build target;
/// 4. `docker`, in a container;
/// 5. `desktop`, on a person's desktop ([`is_desktop`]);
/// 6. `server`.
#[must_use]
pub fn host_kind() -> String {
    if let Some(k) = std::env::var(HOST_KIND_ENV).ok().as_deref().and_then(slug) {
        return k;
    }
    if crate::deployment::is_managed() {
        return std::env::var("CIRIS_AGENT_ID")
            .ok()
            .as_deref()
            .and_then(slug)
            .unwrap_or_else(|| "docker".to_owned());
    }
    if cfg!(target_os = "android") {
        return "android".to_owned();
    }
    if cfg!(target_os = "ios") {
        return "ios".to_owned();
    }
    if in_container() {
        return "docker".to_owned();
    }
    if is_desktop() {
        return "desktop".to_owned();
    }
    "server".to_owned()
}

/// Server tier needs a data disk of at least this many bytes: 1 TB (decimal).
pub const SERVER_TIER_MIN_DISK_BYTES: u64 = 1_000_000_000_000;

/// The server-tier reading for this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerTier {
    /// The data disk's total size, in bytes (0 when it could not be read).
    pub disk_total_bytes: u64,
    /// A person's own install: a desktop, a phone, or the desktop app's node.
    pub personal: bool,
    /// Server tier: enough storage and not personal.
    pub qualifies: bool,
}

impl ServerTier {
    /// Read it for the store under `data_dir`.
    #[must_use]
    pub fn detect(data_dir: &std::path::Path) -> Self {
        let disk_total_bytes = fs2::total_space(data_dir).unwrap_or(0);
        let personal = cfg!(any(target_os = "android", target_os = "ios")) || is_desktop();
        Self::of(disk_total_bytes, personal)
    }

    /// The rule, apart from the host reads.
    #[must_use]
    pub const fn of(disk_total_bytes: u64, personal: bool) -> Self {
        Self {
            disk_total_bytes,
            personal,
            qualifies: !personal && disk_total_bytes >= SERVER_TIER_MIN_DISK_BYTES,
        }
    }

    /// Why, in a phrase, for the boot log and the operator surface.
    #[must_use]
    pub const fn why(&self) -> &'static str {
        if self.personal {
            "not server tier: a personal install (desktop, phone or the desktop app)"
        } else if self.qualifies {
            "server tier: a data disk of at least 1 TB, not a personal install"
        } else {
            "not server tier: the data disk is under 1 TB"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slug_is_plain_and_never_a_role_word() {
        assert_eq!(slug("Datum").as_deref(), Some("datum"));
        assert_eq!(slug("scout-2 (prod)").as_deref(), Some("scout2prod"));
        assert_eq!(slug("Agent"), None);
        assert_eq!(slug("user"), None);
        assert_eq!(slug("node"), None);
        assert_eq!(slug("!!"), None);
        assert_eq!(slug(&"x".repeat(40)).map(|s| s.len()), Some(24));
    }

    #[test]
    fn server_tier_needs_the_disk_and_not_a_personal_install() {
        let tb = SERVER_TIER_MIN_DISK_BYTES;
        assert!(ServerTier::of(tb, false).qualifies);
        assert!(ServerTier::of(2 * tb, false).qualifies);
        assert!(!ServerTier::of(tb - 1, false).qualifies, "under 1 TB");
        assert!(
            !ServerTier::of(4 * tb, true).qualifies,
            "a personal install never is"
        );
        assert!(!ServerTier::of(0, false).qualifies, "an unread disk is not");
    }
}
