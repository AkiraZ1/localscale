//! Multi-Cliente registry for the Host role.
//!
//! The original design paired a Host with exactly one Cliente, using the
//! same singular `PeerStore`/`PeerRecord` for both roles. That stays
//! completely unchanged for the Cliente role (a Cliente only ever connects
//! outward to one Host — nothing about that is multi-anything). The Host
//! role, though, needs to remember an arbitrary number of Clientes it has
//! invited: each with its own one-time invitation secret, its own
//! auto-assigned virtual IP, and its own online/offline state — so this
//! lives in its own file and its own type instead of overloading
//! `PeerStore`.
//!
//! A pending entry (an invitation the Host generated but no device has
//! connected with yet) is identified by `invitation_id` and has `node_id:
//! None`. The first successful handshake using that invitation's secret
//! binds the entry to whatever node id the connecting device claims (see
//! `HostKeyResolver` in the transport crate) — from then on, reconnects are
//! looked up directly by that node id instead of being tried against every
//! still-pending secret.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Serialize, Deserialize)]
pub struct HostPeerEntry {
    /// Stable identity for this registry slot, assigned once at invitation
    /// generation and never reused — independent of `node_id`, which isn't
    /// known until the first successful handshake.
    pub invitation_id: String,
    /// The device's claimed identity, learned from its first successful
    /// handshake. `None` for an invitation nobody has used yet.
    pub node_id: Option<String>,
    /// Stored in the same "key-v1-..." transport-key format `PeerStore`
    /// already uses (see `stored_transport_key_from_invitation_secret`).
    pub invitation_secret: String,
    pub virtual_ip: String,
    pub revoked: bool,
    pub created_unix: u64,
}

pub struct HostPeerRegistry {
    path: PathBuf,
    entries: Vec<HostPeerEntry>,
}

impl HostPeerRegistry {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let entries = match std::fs::read_to_string(&path) {
            Ok(body) => serde_json::from_str(&body).unwrap_or_default(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        Ok(Self { path, entries })
    }

    pub fn entries(&self) -> &[HostPeerEntry] {
        &self.entries
    }

    /// Registers a freshly generated invitation as a new pending slot.
    pub fn add_pending(
        &mut self,
        invitation_id: String,
        invitation_secret: String,
        virtual_ip: String,
        created_unix: u64,
    ) -> std::io::Result<()> {
        self.entries.push(HostPeerEntry {
            invitation_id,
            node_id: None,
            invitation_secret,
            virtual_ip,
            revoked: false,
            created_unix,
        });
        self.persist()
    }

    /// Permanently associates a pending invitation with the node id whose
    /// handshake just used it successfully (see `AuthenticatedStream::
    /// matched_key_tag`). A no-op if the tag is already bound or unknown —
    /// callers don't need to distinguish "already bound" from "first bind".
    pub fn bind(&mut self, invitation_id: &str, node_id: &str) -> std::io::Result<()> {
        let mut changed = false;
        for entry in &mut self.entries {
            if entry.invitation_id == invitation_id && entry.node_id.is_none() {
                entry.node_id = Some(node_id.to_string());
                changed = true;
            }
        }
        if changed {
            self.persist()?;
        }
        Ok(())
    }

    /// Removes the entry matching `id` — either a bound Cliente's real
    /// `node_id`, or (for an invitation nobody has connected with yet,
    /// which has no `node_id` at all) the same
    /// `"convite-pendente-<invitation_id prefix>"` display form that
    /// `devices_status` hands the UI for that entry, so removing a still-
    /// pending invitation from the device list actually works instead of
    /// silently matching nothing.
    pub fn remove(&mut self, id: &str) -> std::io::Result<()> {
        let before = self.entries.len();
        self.entries.retain(|entry| {
            if entry.node_id.as_deref() == Some(id) {
                return false;
            }
            if entry.node_id.is_none() {
                if let Some(prefix) = id.strip_prefix("convite-pendente-") {
                    if !prefix.is_empty() && entry.invitation_id.starts_with(prefix) {
                        return false;
                    }
                }
            }
            true
        });
        if self.entries.len() != before {
            self.persist()?;
        }
        Ok(())
    }

    /// Candidate keys for a handshake claiming `claimed_node_id`: the one
    /// exact match if this id was already bound to a specific entry before,
    /// otherwise every still-pending (unbound, not revoked) invitation —
    /// see `host_registry` module docs and `HostKeyResolver`.
    pub fn candidates_for(&self, claimed_node_id: &str) -> Vec<(String, String)> {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.node_id.as_deref() == Some(claimed_node_id) && !entry.revoked)
        {
            return vec![(entry.invitation_id.clone(), entry.invitation_secret.clone())];
        }
        self.entries
            .iter()
            .filter(|entry| entry.node_id.is_none() && !entry.revoked)
            .map(|entry| (entry.invitation_id.clone(), entry.invitation_secret.clone()))
            .collect()
    }

    /// The next unused address in `<network_prefix>.2`.. `<network_prefix>.254`
    /// (`.1` is reserved for the Host's own address, `.255` for broadcast) —
    /// so newly invited devices never collide with one still connected, or
    /// one that was disconnected but not removed.
    pub fn next_free_virtual_ip(&self, network_prefix: &str) -> String {
        let used: HashSet<u8> = self
            .entries
            .iter()
            .filter_map(|entry| entry.virtual_ip.rsplit('.').next())
            .filter_map(|last_octet| last_octet.parse::<u8>().ok())
            .collect();
        for candidate in 2..=254u8 {
            if !used.contains(&candidate) {
                return format!("{network_prefix}.{candidate}");
            }
        }
        // Pool exhausted (253 devices already registered) — degrade to a
        // fixed high address rather than panicking; a real deployment this
        // size needs a bigger prefix, not a crash.
        format!("{network_prefix}.254")
    }

    fn persist(&self) -> std::io::Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let body = serde_json::to_string(&self.entries)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)?;
        crate::restore_real_owner(&self.path);
        Ok(())
    }
}

/// The Host's own virtual IP, persisted independently of any specific
/// Cliente's registry entry — mirrors `RoleStore`'s simple single-line-file
/// shape. Auto-assigned to `<network_prefix>.1` the first time a Host ever
/// generates an invitation, if nothing was configured yet.
pub struct LocalVirtualIpStore {
    path: PathBuf,
    value: Option<String>,
}

impl LocalVirtualIpStore {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let value = match std::fs::read_to_string(&path) {
            Ok(body) => Some(body.trim().to_string()).filter(|v| !v.is_empty()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        Ok(Self { path, value })
    }

    pub fn get(&self) -> Option<&str> {
        self.value.as_deref()
    }

    pub fn set(&mut self, value: &str) -> std::io::Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, value)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)?;
        crate::restore_real_owner(&self.path);
        self.value = Some(value.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "localscale-host-registry-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn pending_entries_are_candidates_until_bound() {
        let path = temp_path("pending");
        let mut registry = HostPeerRegistry::open(&path).unwrap();
        registry
            .add_pending("inv-a".into(), "secret-a".into(), "10.0.0.2".into(), 0)
            .unwrap();
        registry
            .add_pending("inv-b".into(), "secret-b".into(), "10.0.0.3".into(), 0)
            .unwrap();

        let candidates = registry.candidates_for("new-device");
        assert_eq!(candidates.len(), 2);

        registry.bind("inv-a", "new-device").unwrap();
        let candidates = registry.candidates_for("new-device");
        assert_eq!(candidates, vec![("inv-a".to_string(), "secret-a".to_string())]);

        // A different, still-unbound claimed id still sees only the
        // remaining pending invitation.
        let candidates = registry.candidates_for("someone-else");
        assert_eq!(candidates, vec![("inv-b".to_string(), "secret-b".to_string())]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ip_pool_skips_used_addresses_and_reuses_freed_ones() {
        let path = temp_path("ip-pool");
        let mut registry = HostPeerRegistry::open(&path).unwrap();
        assert_eq!(registry.next_free_virtual_ip("10.0.0"), "10.0.0.2");
        registry
            .add_pending("a".into(), "s".into(), "10.0.0.2".into(), 0)
            .unwrap();
        assert_eq!(registry.next_free_virtual_ip("10.0.0"), "10.0.0.3");
        registry
            .add_pending("b".into(), "s".into(), "10.0.0.3".into(), 0)
            .unwrap();
        assert_eq!(registry.next_free_virtual_ip("10.0.0"), "10.0.0.4");

        registry.bind("a", "device-a").unwrap();
        registry.remove("device-a").unwrap();
        assert_eq!(registry.next_free_virtual_ip("10.0.0"), "10.0.0.2");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pending_invitation_can_be_removed_by_its_display_id() {
        let path = temp_path("remove-pending");
        let mut registry = HostPeerRegistry::open(&path).unwrap();
        registry
            .add_pending(
                "inv-abcdefgh12345".into(),
                "secret".into(),
                "10.0.0.2".into(),
                0,
            )
            .unwrap();
        assert_eq!(registry.entries().len(), 1);

        // The exact form `devices_status` hands the UI for a still-pending
        // entry: "convite-pendente-" followed by the first 8 chars of the
        // invitation id.
        registry.remove("convite-pendente-inv-abcd").unwrap();
        assert_eq!(registry.entries().len(), 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn registry_persists_across_reopen() {
        let path = temp_path("persist");
        {
            let mut registry = HostPeerRegistry::open(&path).unwrap();
            registry
                .add_pending("inv".into(), "secret".into(), "10.0.0.2".into(), 42)
                .unwrap();
            registry.bind("inv", "device-a").unwrap();
        }
        let reopened = HostPeerRegistry::open(&path).unwrap();
        assert_eq!(reopened.entries().len(), 1);
        assert_eq!(reopened.entries()[0].node_id.as_deref(), Some("device-a"));
        let _ = std::fs::remove_file(&path);
    }
}
