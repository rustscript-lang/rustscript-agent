//! Owner-scoped, bounded artifact storage for oversized tool results.
//!
//! Objects are written through a retained [`ConfinedFsRoot`]. Errors never
//! include filesystem paths. Cleanup expires owner mappings by TTL and securely
//! unlinks the corresponding confined object from a retained no-follow
//! directory capability; callers must not treat missing objects as proof that
//! a path exists.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rustscript_vm::{
    ConfinedFsLimits, ConfinedFsRoot, ConfinedPublicationState, EnumerationBudget,
    MAX_COMPONENT_BYTES, MAX_READ_BYTES, MAX_TEMP_ATTEMPTS, MAX_WRITE_BYTES,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{ARTIFACT_RECONCILE_OVERHEAD_ENTRIES, ArtifactStoreConfig};

const TEMP_PREFIX: &str = ".rustscript-agent-tmp-";
const MANIFEST_NAME: &str = "manifest.json";
const MANIFEST_VERSION: u32 = 1;

/// Owner identity used to scope artifact retrieval.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArtifactOwner {
    profile: String,
    session: String,
    run: String,
}

impl ArtifactOwner {
    /// Creates an owner triple. Empty labels are accepted and compared exactly.
    pub fn new(
        profile: impl Into<String>,
        session: impl Into<String>,
        run: impl Into<String>,
    ) -> Self {
        Self {
            profile: profile.into(),
            session: session.into(),
            run: run.into(),
        }
    }
}

/// Handle returned after a successful store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredArtifact {
    /// Unguessable object identifier. Never contains path separators.
    pub id: String,
}

/// Path-free artifact-store failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactError {
    code: &'static str,
    message: String,
}

impl ArtifactError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Stable machine-readable error code.
    pub fn code(&self) -> &str {
        self.code
    }

    /// Human-readable message that does not include filesystem paths.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ArtifactError {}

struct ObjectRecord {
    owner: ArtifactOwner,
    size: usize,
    created_at: SystemTime,
    expires_at: SystemTime,
}

struct StoreState {
    objects: HashMap<String, ObjectRecord>,
    reserved: HashMap<String, usize>,
    committed_bytes: usize,
    reserved_bytes: usize,
    now_override: Option<SystemTime>,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    objects: Vec<ManifestObject>,
}

#[derive(Serialize, Deserialize)]
struct ManifestObject {
    id: String,
    profile: String,
    session: String,
    run: String,
    size: u64,
    created_unix_ms: u64,
    expires_unix_ms: u64,
}

/// Bounded, owner-scoped artifact store.
pub struct ArtifactStore {
    config: ArtifactStoreConfig,
    root: ConfinedFsRoot,
    dir: File,
    state: Mutex<StoreState>,
}

impl ArtifactStore {
    /// Opens (and creates, at setup) the configured artifact directory.
    pub fn with_config(config: ArtifactStoreConfig) -> Result<Self, ArtifactError> {
        config
            .validate()
            .map_err(|message| ArtifactError::new("invalid_config", message))?;
        std::fs::create_dir_all(&config.root)
            .map_err(|_| ArtifactError::new("invalid_config", "failed to create artifact store"))?;
        let dir = open_root_dirfd(&config.root)?;
        lock_exclusive(&dir)?;
        let io_budget = store_io_budget(&config);
        let max_entries = reconcile_enumeration_max_entries(config.max_objects)?;
        let limits = ConfinedFsLimits {
            max_read_bytes: io_budget.min(MAX_READ_BYTES),
            max_write_bytes: io_budget.min(MAX_WRITE_BYTES),
            max_entries,
            max_entry_name_bytes: MAX_COMPONENT_BYTES,
            max_temp_attempts: MAX_TEMP_ATTEMPTS.clamp(1, 32),
        };
        let root = ConfinedFsRoot::with_limits(&config.root, limits)
            .map_err(|error| ArtifactError::new("invalid_config", error.message()))?;
        verify_dirfd_matches_root(&root, &dir)?;
        let mut state = load_and_reconcile(&root, &dir, &config)?;
        persist_index(&root, &state)?;
        state.now_override = None;
        Ok(Self {
            config,
            root,
            dir,
            state: Mutex::new(state),
        })
    }

    /// Returns the configured store root. Callers must not leak this in errors.
    pub fn root_path(&self) -> &Path {
        &self.config.root
    }

    /// Returns how many committed objects are currently retained.
    pub fn object_count(&self) -> usize {
        self.state.lock().objects.len()
    }

    /// Returns committed payload bytes currently retained.
    pub fn total_bytes(&self) -> usize {
        self.state.lock().committed_bytes
    }

    /// Overrides the clock used for TTL decisions. Intended for tests.
    pub fn set_now(&self, now: SystemTime) {
        self.state.lock().now_override = Some(now);
    }

    /// Lists committed object ids that still exist as confined regular files.
    pub fn confined_object_names(&self) -> Result<Vec<String>, ArtifactError> {
        let ids: Vec<String> = self.state.lock().objects.keys().cloned().collect();
        let mut names = Vec::new();
        for id in ids {
            let metadata = self.root.metadata(&id).map_err(|_| {
                ArtifactError::new(
                    "invalid_config",
                    "mapped object is missing from confined storage",
                )
            })?;
            if !metadata.is_file() {
                return Err(ArtifactError::new(
                    "invalid_config",
                    "mapped object is not a regular file",
                ));
            }
            names.push(id);
        }
        Ok(names)
    }

    /// Returns confined metadata length for a retained object leaf.
    pub fn confined_object_len(&self, id: &str) -> Result<u64, ArtifactError> {
        if !valid_artifact_id(id) {
            return Err(not_found());
        }
        let metadata = self.root.metadata(id).map_err(|_| not_found())?;
        if !metadata.is_file() {
            return Err(not_found());
        }
        Ok(metadata.len())
    }

    /// Stores `data` for `owner` and returns an unguessable identifier.
    pub fn put(&self, owner: &ArtifactOwner, data: &[u8]) -> Result<StoredArtifact, ArtifactError> {
        if data.len() > self.config.max_object_bytes {
            return Err(ArtifactError::new(
                "artifact_too_large",
                "artifact exceeds the configured object budget",
            ));
        }

        let id = {
            let mut state = self.state.lock();
            self.expire_into(&mut state)?;
            if !self.has_capacity(&state, data.len()) {
                return Err(ArtifactError::new(
                    "artifact_store_exhausted",
                    "artifact store is at capacity",
                ));
            }
            let id = unique_id(&state);
            state.reserved.insert(id.clone(), data.len());
            state.reserved_bytes = state.reserved_bytes.saturating_add(data.len());
            id
        };
        let mut reservation = ReservationGuard {
            store: self,
            id: id.clone(),
            size: data.len(),
            committed: false,
        };

        let published = self.publish_object(&id, data);
        match published {
            Ok(()) => {
                let mut state = self.state.lock();
                state.reserved.remove(&id);
                state.reserved_bytes = state.reserved_bytes.saturating_sub(data.len());
                let created_at = current_time(&state);
                let expires_at = created_at
                    .checked_add(self.config.ttl)
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                state.objects.insert(
                    id.clone(),
                    ObjectRecord {
                        owner: owner.clone(),
                        size: data.len(),
                        created_at,
                        expires_at,
                    },
                );
                state.committed_bytes = state.committed_bytes.saturating_add(data.len());
                if let Err(error) = persist_index(&self.root, &state) {
                    if let Some(record) = state.objects.remove(&id) {
                        state.committed_bytes = state.committed_bytes.saturating_sub(record.size);
                    }
                    drop(state);
                    let _ = unlink_confined_leaf(&self.dir, &id);
                    return Err(error);
                }
                reservation.committed = true;
                Ok(StoredArtifact { id })
            }
            Err(error) => Err(error),
        }
    }

    /// Returns the payload if it exists, is unexpired, and belongs to `owner`.
    pub fn retrieve(&self, owner: &ArtifactOwner, id: &str) -> Result<Vec<u8>, ArtifactError> {
        self.expire_locked()?;
        if !valid_artifact_id(id) {
            return Err(not_found());
        }
        {
            let state = self.state.lock();
            match state.objects.get(id) {
                Some(record) if &record.owner == owner => {}
                _ => return Err(not_found()),
            }
        }
        self.root.read_file(id).map_err(|_| not_found())
    }

    /// Unlinks expired objects and returns how many mappings were removed.
    pub fn cleanup(&self) -> Result<usize, ArtifactError> {
        let mut state = self.state.lock();
        let removed = self.expire_unlinks(&mut state);
        if removed > 0 {
            let _ = persist_index(&self.root, &state);
        }
        Ok(removed)
    }

    fn expire_locked(&self) -> Result<usize, ArtifactError> {
        let mut state = self.state.lock();
        self.expire_into(&mut state)
    }

    fn expire_into(&self, state: &mut StoreState) -> Result<usize, ArtifactError> {
        let removed = self.expire_unlinks(state);
        if removed > 0 {
            persist_index(&self.root, state)?;
        }
        Ok(removed)
    }

    fn expire_unlinks(&self, state: &mut StoreState) -> usize {
        let now = current_time(state);
        let expired: Vec<String> = state
            .objects
            .iter()
            .filter(|(_, record)| now >= record.expires_at)
            .map(|(id, _)| id.clone())
            .collect();
        let mut removed = 0;
        for id in expired {
            if !unlink_confined_leaf(&self.dir, &id) {
                continue;
            }
            if let Some(record) = state.objects.remove(&id) {
                state.committed_bytes = state.committed_bytes.saturating_sub(record.size);
                removed += 1;
            }
        }
        removed
    }

    fn has_capacity(&self, state: &StoreState, extra: usize) -> bool {
        let count = state.objects.len().saturating_add(state.reserved.len());
        if count >= self.config.max_objects {
            return false;
        }
        state
            .committed_bytes
            .checked_add(state.reserved_bytes)
            .and_then(|total| total.checked_add(extra))
            .is_some_and(|total| total <= self.config.max_total_bytes)
    }

    fn publish_object(&self, id: &str, data: &[u8]) -> Result<(), ArtifactError> {
        let mut temp = self
            .root
            .create_temp("", TEMP_PREFIX)
            .map_err(map_store_error)?;
        temp.write_all(data).map_err(map_store_error)?;
        temp.flush().map_err(map_store_error)?;
        temp.sync_all().map_err(map_store_error)?;
        match self.root.atomic_replace(temp, id) {
            Ok(_) => Ok(()),
            Err(error) => match error.publication_state() {
                ConfinedPublicationState::Published { .. } => Ok(()),
                ConfinedPublicationState::Indeterminate { .. } => Err(ArtifactError::new(
                    "publication_indeterminate",
                    "artifact publication could not be classified",
                )),
                ConfinedPublicationState::NotPublished => Err(map_store_error(error)),
            },
        }
    }
}

struct ReservationGuard<'a> {
    store: &'a ArtifactStore,
    id: String,
    size: usize,
    committed: bool,
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        {
            let mut state = self.store.state.lock();
            if state.reserved.remove(&self.id).is_some() {
                state.reserved_bytes = state.reserved_bytes.saturating_sub(self.size);
            }
        }
        let _ = unlink_confined_leaf(&self.store.dir, &self.id);
    }
}

fn store_io_budget(config: &ArtifactStoreConfig) -> usize {
    config
        .max_total_bytes
        .saturating_add(config.max_objects.saturating_mul(512))
        .max(config.max_object_bytes)
        .min(MAX_WRITE_BYTES)
}

/// Directory entries core enumeration examines, including `.` and `..`.
///
/// Adds the shared reconcile overhead so `max_objects` payloads plus
/// `manifest.json`, one leftover index temp, the two core-counted dot
/// entries, and the unpublished-temp safety margin stay within
/// `MAX_ENUM_ENTRIES` without clamping.
fn reconcile_enumeration_max_entries(max_objects: usize) -> Result<usize, ArtifactError> {
    max_objects
        .checked_add(ARTIFACT_RECONCILE_OVERHEAD_ENTRIES)
        .ok_or_else(|| {
            ArtifactError::new(
                "invalid_config",
                "artifact store enumeration budget overflowed",
            )
        })
}

fn reconcile_enumeration_budget(
    config: &ArtifactStoreConfig,
) -> Result<EnumerationBudget, ArtifactError> {
    Ok(EnumerationBudget {
        max_entries: reconcile_enumeration_max_entries(config.max_objects)?,
        max_name_bytes: MAX_COMPONENT_BYTES,
    })
}

fn current_time(state: &StoreState) -> SystemTime {
    state.now_override.unwrap_or_else(SystemTime::now)
}

fn unique_id(state: &StoreState) -> String {
    loop {
        let id = Uuid::new_v4().to_string();
        if !state.objects.contains_key(&id) && !state.reserved.contains_key(&id) {
            return id;
        }
    }
}

fn persist_index(root: &ConfinedFsRoot, state: &StoreState) -> Result<(), ArtifactError> {
    let manifest = Manifest {
        version: MANIFEST_VERSION,
        objects: state
            .objects
            .iter()
            .map(|(id, record)| ManifestObject {
                id: id.clone(),
                profile: record.owner.profile.clone(),
                session: record.owner.session.clone(),
                run: record.owner.run.clone(),
                size: record.size as u64,
                created_unix_ms: unix_ms(record.created_at),
                expires_unix_ms: unix_ms(record.expires_at),
            })
            .collect(),
    };
    let encoded = serde_json::to_vec(&manifest)
        .map_err(|_| ArtifactError::new("invalid_config", "failed to encode artifact index"))?;
    let mut temp = root.create_temp("", TEMP_PREFIX).map_err(map_store_error)?;
    temp.write_all(&encoded).map_err(map_store_error)?;
    temp.flush().map_err(map_store_error)?;
    temp.sync_all().map_err(map_store_error)?;
    match root.atomic_replace(temp, MANIFEST_NAME) {
        Ok(_) => Ok(()),
        Err(error) => match error.publication_state() {
            ConfinedPublicationState::Published { .. } => Ok(()),
            ConfinedPublicationState::Indeterminate { .. } => Err(ArtifactError::new(
                "publication_indeterminate",
                "artifact index publication could not be classified",
            )),
            ConfinedPublicationState::NotPublished => Err(map_store_error(error)),
        },
    }
}

fn load_and_reconcile(
    root: &ConfinedFsRoot,
    dir: &File,
    config: &ArtifactStoreConfig,
) -> Result<StoreState, ArtifactError> {
    let budget = reconcile_enumeration_budget(config)?;
    let disk_entries = root
        .enumerate_with_budget("", budget)
        .map_err(|error| ArtifactError::new("invalid_config", error.message()))?;
    let mut disk_files = Vec::new();
    for entry in disk_entries {
        let Some(name) = entry.name_os().to_str() else {
            return Err(ArtifactError::new(
                "invalid_config",
                "artifact store contains a non-UTF-8 name",
            ));
        };
        if name.starts_with(TEMP_PREFIX) {
            let _ = unlink_confined_leaf(dir, name);
            continue;
        }
        if !entry.metadata().is_file() {
            return Err(ArtifactError::new(
                "invalid_config",
                "artifact store contains a non-file entry",
            ));
        }
        disk_files.push((name.to_string(), entry.metadata().len()));
    }

    let manifest_present = disk_files.iter().any(|(name, _)| name == MANIFEST_NAME);
    let object_files: Vec<(String, u64)> = disk_files
        .into_iter()
        .filter(|(name, _)| name != MANIFEST_NAME)
        .collect();

    if !manifest_present {
        if !object_files.is_empty() {
            return Err(ArtifactError::new(
                "invalid_config",
                "artifact index is missing",
            ));
        }
        return Ok(StoreState {
            objects: HashMap::new(),
            reserved: HashMap::new(),
            committed_bytes: 0,
            reserved_bytes: 0,
            now_override: None,
        });
    }

    let bytes = root
        .read_file(MANIFEST_NAME)
        .map_err(|_| ArtifactError::new("invalid_config", "artifact index is corrupt"))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|_| ArtifactError::new("invalid_config", "artifact index is corrupt"))?;
    if manifest.version != MANIFEST_VERSION {
        return Err(ArtifactError::new(
            "invalid_config",
            "artifact index is corrupt",
        ));
    }

    let disk_map: HashMap<String, u64> = object_files.into_iter().collect();
    let now = SystemTime::now();
    let mut objects = HashMap::new();
    let mut committed_bytes = 0usize;
    let mut keep: HashMap<String, ()> = HashMap::new();

    for item in manifest.objects {
        if !valid_artifact_id(&item.id) {
            return Err(ArtifactError::new(
                "invalid_config",
                "artifact index is corrupt",
            ));
        }
        keep.insert(item.id.clone(), ());
        let Some(&disk_len) = disk_map.get(&item.id) else {
            continue;
        };
        let expires_at = from_unix_ms(item.expires_unix_ms);
        if now >= expires_at {
            let _ = unlink_confined_leaf(dir, &item.id);
            continue;
        }
        let size = usize::try_from(disk_len).unwrap_or(usize::MAX);
        committed_bytes = committed_bytes.saturating_add(size);
        objects.insert(
            item.id,
            ObjectRecord {
                owner: ArtifactOwner::new(item.profile, item.session, item.run),
                size,
                created_at: from_unix_ms(item.created_unix_ms),
                expires_at,
            },
        );
    }

    for name in disk_map.keys() {
        if !keep.contains_key(name) {
            let _ = unlink_confined_leaf(dir, name);
        }
    }

    if objects.len() > config.max_objects || committed_bytes > config.max_total_bytes {
        return Err(ArtifactError::new(
            "invalid_config",
            "artifact store exceeds configured capacity",
        ));
    }

    Ok(StoreState {
        objects,
        reserved: HashMap::new(),
        committed_bytes,
        reserved_bytes: 0,
        now_override: None,
    })
}

fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn from_unix_ms(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

fn open_root_dirfd(path: &Path) -> Result<File, ArtifactError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(unix_dir::O_DIRECTORY | unix_dir::O_NOFOLLOW | unix_dir::O_CLOEXEC)
            .open(path)
            .map_err(|_| ArtifactError::new("invalid_config", "failed to open artifact store"))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ArtifactError::new(
            "invalid_config",
            "artifact store requires a Unix directory capability",
        ))
    }
}

fn lock_exclusive(dir: &File) -> Result<(), ArtifactError> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let result =
            unsafe { unix_dir::flock(dir.as_raw_fd(), unix_dir::LOCK_EX | unix_dir::LOCK_NB) };
        if result == 0 {
            Ok(())
        } else {
            Err(ArtifactError::new(
                "artifact_store_busy",
                "artifact store is already open",
            ))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err(ArtifactError::new(
            "invalid_config",
            "artifact store requires a Unix directory capability",
        ))
    }
}

fn verify_dirfd_matches_root(root: &ConfinedFsRoot, dir: &File) -> Result<(), ArtifactError> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let mut temp = root.create_temp("", TEMP_PREFIX).map_err(map_store_error)?;
        temp.write_all(b"identity").map_err(map_store_error)?;
        temp.flush().map_err(map_store_error)?;
        let name = std::ffi::CString::new(temp.name())
            .map_err(|_| ArtifactError::new("invalid_config", "failed to verify artifact store"))?;
        let fd = unsafe {
            unix_dir::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                unix_dir::O_RDONLY | unix_dir::O_NOFOLLOW | unix_dir::O_CLOEXEC,
            )
        };
        if fd < 0 {
            drop(temp);
            return Err(ArtifactError::new(
                "invalid_config",
                "artifact store identity check failed",
            ));
        }
        let mut buffer = [0_u8; 8];
        let read = unsafe { unix_dir::read(fd, buffer.as_mut_ptr(), buffer.len()) };
        unsafe { unix_dir::close(fd) };
        drop(temp);
        if read != 8 || &buffer != b"identity" {
            return Err(ArtifactError::new(
                "invalid_config",
                "artifact store identity check failed",
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (root, dir);
        Err(ArtifactError::new(
            "invalid_config",
            "artifact store requires a Unix directory capability",
        ))
    }
}

fn unlink_confined_leaf(dir: &File, id: &str) -> bool {
    let Ok(name) = std::ffi::CString::new(id) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let result = unsafe { unix_dir::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return true;
        }
        std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, name);
        false
    }
}

#[cfg(unix)]
mod unix_dir {
    pub const O_RDONLY: i32 = 0;
    pub const O_DIRECTORY: i32 = 0o200000;
    pub const O_NOFOLLOW: i32 = 0o400000;
    pub const O_CLOEXEC: i32 = 0o2000000;
    pub const LOCK_EX: i32 = 2;
    pub const LOCK_NB: i32 = 4;

    unsafe extern "C" {
        pub fn unlinkat(dirfd: i32, pathname: *const std::ffi::c_char, flags: i32) -> i32;
        pub fn flock(fd: i32, operation: i32) -> i32;
        pub fn openat(dirfd: i32, pathname: *const std::ffi::c_char, flags: i32) -> i32;
        pub fn close(fd: i32) -> i32;
        pub fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    }
}

fn valid_artifact_id(id: &str) -> bool {
    !id.is_empty()
        && !id.contains('/')
        && !id.contains('\\')
        && !id.contains("..")
        && !id.contains('\0')
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn not_found() -> ArtifactError {
    ArtifactError::new("artifact_not_found", "artifact not found")
}

fn map_store_error(error: rustscript_vm::ConfinedFsError) -> ArtifactError {
    match error.publication_state() {
        ConfinedPublicationState::Indeterminate { .. } => ArtifactError::new(
            "publication_indeterminate",
            "artifact publication could not be classified",
        ),
        _ => ArtifactError::new("invalid_config", error.message()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MAX_ARTIFACT_OBJECTS;
    use rustscript_vm::MAX_ENUM_ENTRIES;

    #[test]
    fn enumeration_budget_uses_checked_max_objects_plus_metadata_overhead() {
        assert_eq!(ARTIFACT_RECONCILE_OVERHEAD_ENTRIES, 12);
        assert_eq!(
            reconcile_enumeration_max_entries(16).unwrap(),
            16 + ARTIFACT_RECONCILE_OVERHEAD_ENTRIES
        );
        assert_ne!(reconcile_enumeration_max_entries(16).unwrap(), 4096);
        assert_ne!(
            reconcile_enumeration_max_entries(16).unwrap(),
            MAX_ENUM_ENTRIES
        );
        assert_ne!(reconcile_enumeration_max_entries(16).unwrap(), 1_000_000);
        assert!(reconcile_enumeration_max_entries(usize::MAX).is_err());
    }

    #[test]
    fn artifact_object_ceiling_fits_core_enumeration_without_clamp() {
        let accepted = MAX_ENUM_ENTRIES - ARTIFACT_RECONCILE_OVERHEAD_ENTRIES;
        assert_eq!(MAX_ARTIFACT_OBJECTS, accepted);

        let mut config = ArtifactStoreConfig::for_root("/tmp/rustscript-agent-artifact-ceiling");
        config.max_objects = accepted;
        config
            .validate()
            .expect("accepted payload ceiling must validate");
        config.max_objects = accepted + 1;
        assert!(
            config.validate().is_err(),
            "one above the reconciled ceiling must be rejected"
        );

        assert_eq!(
            reconcile_enumeration_max_entries(accepted).unwrap(),
            MAX_ENUM_ENTRIES
        );
        assert_eq!(
            reconcile_enumeration_max_entries(MAX_ARTIFACT_OBJECTS).unwrap(),
            MAX_ENUM_ENTRIES
        );
        assert_eq!(
            reconcile_enumeration_max_entries(accepted)
                .unwrap()
                .checked_sub(accepted),
            Some(ARTIFACT_RECONCILE_OVERHEAD_ENTRIES)
        );
    }
}
