//! Native reservations and leases. No lease lock spans filesystem or SDK IO.
use super::{broker::validate_id, journal::ManagedObjectKind, tree_store};
use crate::{
    capabilities::vm_io::{ConfinedFsRoot, confined_fs::EnumerationBudget},
    config::ManagedWorkspaceConfig,
    gateway::store::GatewayPersistence,
};
use parking_lot::Mutex;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Copy, Default)]
struct Charge {
    objects: usize,
    bytes: u64,
}

#[cfg(test)]
use super::{EffectCancellation, EffectDeadline};
#[cfg(test)]
use std::time::Instant;

/// Startup-only traversal authority: configured work quotas, never a live call.
pub(super) struct StartupCensus {
    #[cfg(test)]
    deadline: EffectDeadline,
    #[cfg(test)]
    checks: std::sync::atomic::AtomicUsize,
}
impl StartupCensus {
    #[cfg(test)]
    pub(super) fn observed_work_for_test(&self) -> usize {
        self.checks.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(super) fn checkpoint(&self) {
        #[cfg(test)]
        self.checks
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
    pub(super) fn new() -> Self {
        Self {
            #[cfg(test)]
            deadline: EffectDeadline::at(Instant::now()),
            #[cfg(test)]
            checks: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
#[path = "retention_tests.rs"]
mod tests;

struct Entry {
    bytes: u64,
    leases: usize,
    unknown: bool,
}
struct State {
    used: Charge,
    entries: BTreeMap<String, Entry>,
}
pub(crate) struct ManagedObjectLeaseRegistry {
    max: Charge,
    state: Mutex<State>,
}
pub(crate) struct ManagedCallReservation {
    registry: Arc<ManagedObjectLeaseRegistry>,
    remaining: Mutex<Charge>,
}
pub(crate) struct ManagedObjectTicket {
    registry: Arc<ManagedObjectLeaseRegistry>,
    bytes: u64,
    id: Option<String>,
    active: bool,
}
pub(crate) struct ManagedObjectLease {
    registry: Arc<ManagedObjectLeaseRegistry>,
    id: String,
}

impl ManagedObjectLeaseRegistry {
    #[cfg(test)]
    pub(crate) fn lease_existing_for_test(
        self: &Arc<Self>,
        id: &str,
    ) -> Result<ManagedObjectLease, String> {
        let mut state = self.state.lock();
        let entry = state
            .entries
            .get_mut(id)
            .ok_or("Native object lease target missing")?;
        entry.leases += 1;
        Ok(ManagedObjectLease {
            registry: Arc::clone(self),
            id: id.into(),
        })
    }
    pub(crate) fn open(
        config: &ManagedWorkspaceConfig,
        root: &ConfinedFsRoot,
        persistence: &GatewayPersistence,
        store_id: &str,
        census: &StartupCensus,
    ) -> Result<Arc<Self>, String> {
        let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
        let mut physical = BTreeMap::new();
        for entry in root
            .enumerate_with_budget(
                "",
                EnumerationBudget {
                    max_entries: 16,
                    max_name_bytes: 255,
                },
            )
            .map_err(|e| e.to_string())?
        {
            if ![
                "lease", "store-id", "trees", "results", "details", "views", "staging",
            ]
            .contains(&entry.name())
            {
                return Err(
                    "managed store contains an unknown namespace; retained unchanged".into(),
                );
            }
        }
        for namespace in ["trees", "results", "details", "views", "staging"] {
            let observed = root
                .enumerate_with_budget(
                    namespace,
                    EnumerationBudget {
                        max_entries: config.retention.max_objects + 2,
                        max_name_bytes: 255,
                    },
                )
                .map_err(|e| e.to_string())?;
            for item in observed {
                let id = item
                    .name_os()
                    .to_str()
                    .ok_or("managed census name must be UTF-8")?;
                let prefix = match namespace {
                    "trees" => "tree",
                    "results" => "result",
                    "details" => "intent",
                    "views" => "view",
                    _ => id.split_once('-').ok_or("managed staging name invalid")?.0,
                };
                validate_id(prefix, id)?;
                if entries.contains_key(id) {
                    return Err("managed object appears in multiple namespaces".into());
                }
                let metadata = item.metadata();
                let mut physical_entries = 1;
                let bytes = if namespace == "views" {
                    if !metadata.is_dir() {
                        return Err("managed view has wrong kind".into());
                    }
                    config.quota.max_bytes
                } else if metadata.is_dir() && prefix == "tree" {
                    let directory = root
                        .subroot(&format!("{namespace}/{id}"), root.limits())
                        .map_err(|e| e.to_string())?;
                    let usage = tree_store::startup_census_usage_from_fd(
                        &directory
                            .duplicate_descriptor()
                            .map_err(|e| e.to_string())?,
                        &config.quota,
                        census,
                    )
                    .map_err(|e| e.to_string())?;
                    physical_entries = usage.entries;
                    usage.bytes
                } else if metadata.is_file()
                    && metadata.link_count() == 1
                    && ["result", "intent"].contains(&prefix)
                {
                    metadata.len()
                } else {
                    return Err("managed census contains unsupported object".into());
                };
                physical.insert(id.to_string(), (prefix.to_string(), physical_entries));
                entries.insert(
                    id.to_string(),
                    Entry {
                        bytes,
                        leases: 0,
                        unknown: true,
                    },
                );
                if entries.len() > config.retention.max_objects {
                    return Err("managed retained object capacity exceeded".into());
                }
            }
        }
        for object in persistence
            .managed_object_census()
            .map_err(|e| e.to_string())?
        {
            if object.store_id != store_id {
                return Err("managed store marker differs from durable registry".into());
            }
            let prefix = match object.object_kind {
                ManagedObjectKind::Tree => "tree",
                ManagedObjectKind::CanonicalResult => "result",
                ManagedObjectKind::IntentDetails => "intent",
            };
            validate_id(prefix, &object.object_id)?;
            let bytes = object
                .byte_count
                .parse::<u64>()
                .map_err(|_| "managed census byte count invalid")?;
            if let Some(entry) = entries.get_mut(&object.object_id) {
                let expected_entries = object
                    .entry_count
                    .parse::<u64>()
                    .map_err(|_| "managed census entry count invalid")?;
                let expected_format = match object.object_kind {
                    ManagedObjectKind::Tree => "agent.managed-tree/v1",
                    ManagedObjectKind::CanonicalResult => "agent.canonical-tool-result/v1",
                    ManagedObjectKind::IntentDetails => "agent.intent-details/v1",
                };
                if entry.bytes != bytes
                    || physical.get(&object.object_id)
                        != Some(&(prefix.to_string(), expected_entries))
                    || object.object_format != expected_format
                {
                    return Err("managed object size differs from durable registry".into());
                }
                entry.unknown = false;
            } else {
                entries.insert(
                    object.object_id,
                    Entry {
                        bytes,
                        leases: 0,
                        unknown: true,
                    },
                );
            }
        }
        let used = Charge {
            objects: entries.len(),
            bytes: entries
                .values()
                .try_fold(0u64, |sum, entry| sum.checked_add(entry.bytes))
                .ok_or("managed census bytes overflow")?,
        };
        if used.objects > config.retention.max_objects || used.bytes > config.retention.max_bytes {
            return Err("managed retained capacity exceeded".into());
        }
        Ok(Arc::new(Self {
            max: Charge {
                objects: config.retention.max_objects,
                bytes: config.retention.max_bytes,
            },
            state: Mutex::new(State { used, entries }),
        }))
    }
    pub(crate) fn reserve(
        self: &Arc<Self>,
        objects: usize,
        bytes: u64,
    ) -> Result<Arc<ManagedCallReservation>, String> {
        let mut state = self.state.lock();
        let count = state
            .used
            .objects
            .checked_add(objects)
            .ok_or("managed reservation overflow")?;
        let total = state
            .used
            .bytes
            .checked_add(bytes)
            .ok_or("managed reservation overflow")?;
        if count > self.max.objects || total > self.max.bytes {
            return Err("managed retention capacity exceeded".into());
        }
        state.used = Charge {
            objects: count,
            bytes: total,
        };
        Ok(Arc::new(ManagedCallReservation {
            registry: Arc::clone(self),
            remaining: Mutex::new(Charge { objects, bytes }),
        }))
    }
    pub(crate) fn single(self: &Arc<Self>, bytes: u64) -> Result<ManagedObjectTicket, String> {
        self.reserve(1, bytes)?.take_object(bytes)
    }
    fn release(&self, charge: Charge) {
        let mut state = self.state.lock();
        state.used.objects -= charge.objects;
        state.used.bytes -= charge.bytes;
    }
}
impl ManagedCallReservation {
    pub(crate) fn take_object(&self, bytes: u64) -> Result<ManagedObjectTicket, String> {
        let mut remaining = self.remaining.lock();
        if remaining.objects == 0 || remaining.bytes < bytes {
            return Err("managed object reservation exhausted".into());
        }
        remaining.objects -= 1;
        remaining.bytes -= bytes;
        Ok(ManagedObjectTicket {
            registry: Arc::clone(&self.registry),
            bytes,
            id: None,
            active: true,
        })
    }
    pub(crate) fn release_unspent(&self) {
        let remaining = std::mem::take(&mut *self.remaining.lock());
        self.registry.release(remaining);
    }
}
impl Drop for ManagedCallReservation {
    fn drop(&mut self) {
        self.release_unspent();
    }
}
impl ManagedObjectTicket {
    pub(crate) fn start(&mut self, id: &str) -> Result<(), String> {
        if self.id.is_some() {
            return Err("managed object ticket already used".into());
        }
        let mut state = self.registry.state.lock();
        if state.entries.contains_key(id) {
            return Err("managed object identity already retained".into());
        }
        state.entries.insert(
            id.into(),
            Entry {
                bytes: self.bytes,
                leases: 1,
                unknown: false,
            },
        );
        self.id = Some(id.into());
        Ok(())
    }
    pub(crate) fn seal(mut self, bytes: u64) -> Result<ManagedObjectLease, String> {
        if bytes > self.bytes {
            return Err("managed object exceeded its reservation".into());
        }
        let id = self.id.clone().ok_or("managed object has not started")?;
        {
            let mut state = self.registry.state.lock();
            state.used.bytes -= self.bytes - bytes;
            let entry = state
                .entries
                .get_mut(&id)
                .ok_or("managed object lease missing")?;
            entry.bytes = bytes;
        }
        self.active = false;
        Ok(ManagedObjectLease {
            registry: Arc::clone(&self.registry),
            id,
        })
    }
    pub(crate) fn sole_known_lease(&self) -> bool {
        self.id
            .as_ref()
            .and_then(|id| {
                self.registry
                    .state
                    .lock()
                    .entries
                    .get(id)
                    .map(|entry| entry.leases == 1 && !entry.unknown)
            })
            .unwrap_or(false)
    }
    pub(crate) fn retire(mut self) -> Result<(), String> {
        let id = self.id.as_ref().ok_or("managed object has not started")?;
        let mut state = self.registry.state.lock();
        let entry = state
            .entries
            .get(id)
            .ok_or("managed object lease missing")?;
        if entry.leases != 1 || entry.unknown {
            return Err("managed object lease is not exclusively settled".into());
        }
        state.entries.remove(id);
        state.used.objects -= 1;
        state.used.bytes -= self.bytes;
        self.active = false;
        Ok(())
    }
}
impl Drop for ManagedObjectTicket {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(id) = &self.id {
            let mut state = self.registry.state.lock();
            if let Some(entry) = state.entries.get_mut(id) {
                entry.unknown = true;
                entry.leases -= 1;
            }
        } else {
            self.registry.release(Charge {
                objects: 1,
                bytes: self.bytes,
            });
        }
    }
}
impl Drop for ManagedObjectLease {
    fn drop(&mut self) {
        if let Some(entry) = self.registry.state.lock().entries.get_mut(&self.id) {
            entry.leases -= 1;
        }
    }
}
