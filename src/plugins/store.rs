//! Immutable plugin package store.
//!
//! Installed bytes are the only bytes later compilation may see. A signature
//! proves publisher identity; it does not add a capability.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use ring::digest;
use ring::signature::{ED25519, UnparsedPublicKey};

use super::error::{PluginError, PluginErrorKind};
use super::manifest::{PluginManifest, parse_plugin_manifest, safe_relative};
use super::resolve::GraphLock;

const SIGNATURE_FILE: &str = "signature.ed25519";
const MAX_CAPTURE_FILE: usize = 1024 * 1024;
const MAX_CAPTURE_TOTAL: usize = 8 * 1024 * 1024;
const MAX_CAPTURE_FILES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublisherKey {
    pub publisher: String,
    pub verifying_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallAuthorization {
    pub admin: bool,
    pub accepted_publishers: Vec<PublisherKey>,
    pub unsigned_dev_space: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageTrust {
    AcceptedPublisher,
    DevUnsigned,
    /// Closed catalog bytes installed by the trusted embedder, not a signature
    /// or a dev-unsigned bypass.
    EmbeddingOwnedBuiltin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRevision {
    pub artifact_id: String,
    pub trust: PackageTrust,
    manifest: PluginManifest,
}

impl PackageRevision {
    pub fn declared_capabilities(&self) -> Vec<String> {
        self.manifest.declared_capabilities()
    }
}

#[derive(Clone, Debug)]
pub struct InstalledPackage {
    pub artifact_id: String,
    pub trust: PackageTrust,
    pub manifest: PluginManifest,
    pub sources: BTreeMap<String, Vec<u8>>,
}

impl InstalledPackage {
    pub fn new(
        artifact_id: &str,
        manifest: PluginManifest,
        sources: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.to_string(),
            trust: PackageTrust::DevUnsigned,
            manifest,
            sources,
        }
    }
}

pub struct PackageStore {
    root: PathBuf,
    artifacts: OwnedFd,
    ledger: OwnedFd,
    policy: Mutex<Option<InstallAuthorization>>,
    verified: Mutex<Option<Vec<InstalledPackage>>>,
    // One immutable compiled graph; no VM, owner, grant, or mutable registry.
    pub(super) prepared: Mutex<Option<(GraphLock, super::prepare::PreparedGraph)>>,
}

impl PackageStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PluginError> {
        let root = root.into();
        reject_symlink_path(&root)?;
        fs::create_dir_all(root.join("artifacts"))
            .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "store"))?;
        fs::create_dir_all(root.join("ledger"))
            .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "ledger"))?;
        let artifacts = open_dir_nofollow(&root.join("artifacts"))?;
        let ledger = open_dir_nofollow(&root.join("ledger"))?;
        Ok(Self {
            root,
            artifacts,
            ledger,
            policy: Mutex::new(None),
            verified: Mutex::new(None),
            prepared: Mutex::new(None),
        })
    }

    pub fn bind_policy(&self, auth: &InstallAuthorization) {
        let mut policy = self.policy.lock().unwrap_or_else(|err| err.into_inner());
        *policy = Some(auth.clone());
        drop(policy);
        self.forget_verified();
    }

    pub fn signature_payload(&self, package: &Path) -> Result<Vec<u8>, PluginError> {
        let files = read_package(package)?;
        Ok(payload_bytes(&files))
    }

    pub fn install(
        &self,
        package: &Path,
        auth: &InstallAuthorization,
    ) -> Result<PackageRevision, PluginError> {
        if !auth.admin {
            return Err(PluginError::new(
                PluginErrorKind::PublisherUnauthorized,
                "admin authorization required",
            ));
        }
        self.bind_policy(auth);
        let files = read_package(package)?;
        let manifest_bytes = files
            .get("manifest.yaml")
            .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "manifest.yaml"))?;
        let manifest_text = std::str::from_utf8(manifest_bytes)
            .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "manifest.yaml"))?;
        let manifest = parse_plugin_manifest(manifest_text)?;
        if !files.contains_key(&manifest.entry.path) {
            return Err(PluginError::new(
                PluginErrorKind::UnknownField,
                "entry source",
            ));
        }
        let payload = payload_bytes(&files);
        let artifact_id = payload_artifact_id(&payload);
        let trust = authorize(package, auth, &manifest, &files, &payload)?;
        if let Some(existing) = self.find_version(&manifest.id, &manifest.version)? {
            if existing == artifact_id {
                return self.revision_from_capture(&artifact_id);
            }
            return Err(PluginError::new(
                PluginErrorKind::VersionOverwrite,
                format!("{} {}", manifest.id, manifest.version),
            ));
        }
        self.write_artifact(&artifact_id, &files, trust, &manifest.publisher, &payload)?;
        Ok(PackageRevision {
            artifact_id,
            trust,
            manifest,
        })
    }

    /// Installs the closed embedded tool catalog as an immutable builtin.
    /// A signature or dev-unsigned space is not accepted for these bytes.
    pub fn install_embedding_owned(&self) -> Result<PackageRevision, PluginError> {
        let files = crate::runtime::native_tools::embedding_package_files()
            .map_err(|message| PluginError::new(PluginErrorKind::CompileFailed, message))?;
        let manifest_bytes = files
            .get("manifest.yaml")
            .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "manifest.yaml"))?;
        let manifest = parse_plugin_manifest(
            std::str::from_utf8(manifest_bytes)
                .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "manifest"))?,
        )?;
        if manifest.id != crate::runtime::native_tools::EMBEDDING_PACKAGE_ID {
            return Err(PluginError::new(
                PluginErrorKind::ContractIncompatible,
                "embedding package",
            ));
        }
        let payload = payload_bytes(&files);
        let artifact_id = payload_artifact_id(&payload);
        if let Some(existing) = self.find_version(&manifest.id, &manifest.version)? {
            if existing == artifact_id {
                return self.revision_from_capture(&artifact_id);
            }
            return Err(PluginError::new(
                PluginErrorKind::VersionOverwrite,
                format!("{} {}", manifest.id, manifest.version),
            ));
        }
        self.write_artifact(
            &artifact_id,
            &files,
            PackageTrust::EmbeddingOwnedBuiltin,
            &manifest.publisher,
            &payload,
        )?;
        Ok(PackageRevision {
            artifact_id,
            trust: PackageTrust::EmbeddingOwnedBuiltin,
            manifest,
        })
    }

    pub fn load_installed(&self) -> Result<Vec<InstalledPackage>, PluginError> {
        reject_symlink_path(&self.root.join("artifacts"))?;
        reject_symlink_path(&self.root.join("ledger"))?;
        let mut packages = Vec::new();
        for name in list_dir(&self.artifacts)? {
            if name.ends_with(".tmp") {
                continue;
            }
            packages.push(self.read_installed(&name)?);
        }
        let mut verified = self.verified.lock().unwrap_or_else(|err| err.into_inner());
        *verified = Some(packages.clone());
        Ok(packages)
    }

    pub(crate) fn verified_capture(
        &self,
        required: &[(&str, &str)],
    ) -> Result<Vec<InstalledPackage>, PluginError> {
        let cached = self.verified.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(packages) = cached.as_ref()
            && required.iter().all(|(id, artifact_id)| {
                packages.iter().any(|package| {
                    package.manifest.id == *id && package.artifact_id == *artifact_id
                })
            })
        {
            return Ok(packages.clone());
        }
        drop(cached);
        let mut packages = Vec::with_capacity(required.len());
        for (id, artifact_id) in required {
            let installed = self.read_installed(artifact_id)?;
            if installed.manifest.id != *id || installed.artifact_id != *artifact_id {
                return Err(PluginError::new(
                    PluginErrorKind::PathEscape,
                    "captured artifact identity",
                ));
            }
            packages.push(installed);
        }
        Ok(packages)
    }

    fn forget_verified(&self) {
        let mut verified = self.verified.lock().unwrap_or_else(|err| err.into_inner());
        *verified = None;
        *self
            .prepared
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }

    fn find_version(&self, id: &str, version: &str) -> Result<Option<String>, PluginError> {
        for package in self.load_installed()? {
            if package.manifest.id == id && package.manifest.version == version {
                return Ok(Some(package.artifact_id));
            }
        }
        Ok(None)
    }

    fn revision_from_capture(&self, artifact_id: &str) -> Result<PackageRevision, PluginError> {
        let installed = self.read_installed(artifact_id)?;
        Ok(PackageRevision {
            artifact_id: installed.artifact_id,
            trust: installed.trust,
            manifest: installed.manifest,
        })
    }

    fn write_artifact(
        &self,
        artifact_id: &str,
        files: &BTreeMap<String, Vec<u8>>,
        trust: PackageTrust,
        publisher: &str,
        payload: &[u8],
    ) -> Result<(), PluginError> {
        if list_dir(&self.artifacts)?
            .iter()
            .any(|name| name == artifact_id)
        {
            let captured = self.capture(artifact_id)?;
            if captured.files == *files && self.ledger_matches(artifact_id, payload)? {
                return Ok(());
            }
            return Err(PluginError::new(
                PluginErrorKind::VersionOverwrite,
                artifact_id,
            ));
        }
        let temporary = format!("{artifact_id}.tmp");
        if list_dir(&self.artifacts)?
            .iter()
            .any(|name| name == &temporary)
        {
            remove_tree(&self.artifacts, &temporary)?;
        }
        mkdir_at(&self.artifacts, &temporary)?;
        let temp_dir = open_dir_at(&self.artifacts, &temporary)?;
        mkdir_at(&temp_dir, "sources")?;
        let sources = open_dir_at(&temp_dir, "sources")?;
        for (path, bytes) in files {
            if path == "manifest.yaml" {
                write_file_at(&temp_dir, "manifest.yaml", bytes)?;
            } else if path == SIGNATURE_FILE {
                write_file_at(&temp_dir, SIGNATURE_FILE, bytes)?;
            } else {
                write_relative(&sources, path, bytes)?;
            }
        }
        sync_dir(&temp_dir)?;
        sync_dir(&sources)?;
        rename_at(&self.artifacts, &temporary, artifact_id)?;
        sync_dir(&self.artifacts)?;
        self.forget_verified();
        if let Err(err) = self.write_ledger(artifact_id, trust, publisher, payload) {
            let _ = remove_tree(&self.artifacts, artifact_id);
            return Err(err);
        }
        Ok(())
    }

    pub(crate) fn read_installed(
        &self,
        artifact_id: &str,
    ) -> Result<InstalledPackage, PluginError> {
        let captured = self.capture(artifact_id)?;
        let payload = payload_bytes(&captured.files);
        if payload_artifact_id(&payload) != artifact_id {
            return Err(PluginError::new(
                PluginErrorKind::PathEscape,
                "artifact bytes",
            ));
        }
        let ledger = self.read_ledger(artifact_id)?;
        if ledger.payload != payload {
            return Err(PluginError::new(
                PluginErrorKind::PathEscape,
                "artifact ledger",
            ));
        }
        let manifest_bytes = captured
            .files
            .get("manifest.yaml")
            .ok_or_else(|| PluginError::new(PluginErrorKind::UnknownField, "manifest.yaml"))?;
        let manifest = parse_plugin_manifest(
            std::str::from_utf8(manifest_bytes)
                .map_err(|_| PluginError::new(PluginErrorKind::UnknownField, "manifest"))?,
        )?;
        if !captured.files.contains_key(&manifest.entry.path) {
            return Err(PluginError::new(
                PluginErrorKind::UnknownField,
                "entry source",
            ));
        }
        if ledger.publisher != manifest.publisher {
            return Err(PluginError::new(
                PluginErrorKind::PublisherUnauthorized,
                "publisher record",
            ));
        }
        let policy = self.current_policy()?;
        let trust = revalidate(
            &policy,
            &manifest,
            captured.files.get(SIGNATURE_FILE),
            &payload,
            ledger.trust,
        )?;
        let mut sources = BTreeMap::new();
        for (path, bytes) in captured.files {
            if path == "manifest.yaml" || path == SIGNATURE_FILE {
                continue;
            }
            sources.insert(path, bytes);
        }
        Ok(InstalledPackage {
            artifact_id: artifact_id.to_string(),
            trust,
            manifest,
            sources,
        })
    }

    fn current_policy(&self) -> Result<InstallAuthorization, PluginError> {
        self.policy
            .lock()
            .map_err(|_| {
                PluginError::new(
                    PluginErrorKind::PublisherUnauthorized,
                    "installation policy",
                )
            })?
            .clone()
            .ok_or_else(|| {
                PluginError::new(
                    PluginErrorKind::PublisherUnauthorized,
                    "installation policy",
                )
            })
    }

    fn ledger_matches(&self, artifact_id: &str, payload: &[u8]) -> Result<bool, PluginError> {
        Ok(self.read_ledger(artifact_id)?.payload == payload)
    }

    fn write_ledger(
        &self,
        artifact_id: &str,
        trust: PackageTrust,
        publisher: &str,
        payload: &[u8],
    ) -> Result<(), PluginError> {
        let bytes = encode_ledger(trust, publisher, payload);
        write_file_at(&self.ledger, artifact_id, &bytes)?;
        sync_dir(&self.ledger)?;
        Ok(())
    }

    fn read_ledger(&self, artifact_id: &str) -> Result<LedgerRecord, PluginError> {
        let fd = open_file_at(&self.ledger, artifact_id)?;
        let bytes = read_limited(fd, MAX_CAPTURE_TOTAL)?;
        decode_ledger(&bytes)
    }

    fn capture(&self, artifact_id: &str) -> Result<CapturedArtifact, PluginError> {
        reject_artifact_id(artifact_id)?;
        let dir = open_dir_at(&self.artifacts, artifact_id)?;
        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for name in list_dir(&dir)? {
            if name == "trust" {
                let meta = open_file_at(&dir, &name);
                if meta.is_err() {
                    return Err(PluginError::new(PluginErrorKind::SymlinkDenied, "trust"));
                }
                continue;
            }
            if name == "sources" {
                let sources = open_dir_at(&dir, "sources")?;
                capture_sources(&sources, "", &mut files, &mut total)?;
                continue;
            }
            if name != "manifest.yaml" && name != SIGNATURE_FILE {
                return Err(PluginError::new(PluginErrorKind::PathEscape, name));
            }
            let bytes = read_limited(open_file_at(&dir, &name)?, MAX_CAPTURE_FILE)?;
            total = total.saturating_add(bytes.len());
            if total > MAX_CAPTURE_TOTAL || files.len() >= MAX_CAPTURE_FILES {
                return Err(PluginError::new(
                    PluginErrorKind::BudgetExceeded,
                    "artifact",
                ));
            }
            files.insert(name, bytes);
        }
        if !files.contains_key("manifest.yaml") {
            return Err(PluginError::new(
                PluginErrorKind::UnknownField,
                "manifest.yaml",
            ));
        }
        Ok(CapturedArtifact { files })
    }
}

fn authorize(
    package: &Path,
    auth: &InstallAuthorization,
    manifest: &PluginManifest,
    files: &BTreeMap<String, Vec<u8>>,
    payload: &[u8],
) -> Result<PackageTrust, PluginError> {
    if let Some(signature) = files.get(SIGNATURE_FILE) {
        return verify_signature(auth, &manifest.publisher, signature, payload);
    }
    if let Some(dev) = &auth.unsigned_dev_space
        && path_inside(dev, package)?
    {
        return Ok(PackageTrust::DevUnsigned);
    }
    Err(PluginError::new(
        PluginErrorKind::PublisherUnauthorized,
        manifest.publisher.clone(),
    ))
}

fn revalidate(
    auth: &InstallAuthorization,
    manifest: &PluginManifest,
    signature: Option<&Vec<u8>>,
    payload: &[u8],
    recorded: PackageTrust,
) -> Result<PackageTrust, PluginError> {
    if recorded == PackageTrust::EmbeddingOwnedBuiltin {
        if signature.is_some() || !crate::runtime::native_tools::embedding_payload_matches(payload)
        {
            return Err(PluginError::new(
                PluginErrorKind::PublisherUnauthorized,
                "embedding payload",
            ));
        }
        let _ = auth;
        return Ok(PackageTrust::EmbeddingOwnedBuiltin);
    }
    if let Some(signature) = signature {
        let trust = verify_signature(auth, &manifest.publisher, signature, payload)?;
        if recorded != PackageTrust::AcceptedPublisher {
            return Err(PluginError::new(
                PluginErrorKind::PublisherUnauthorized,
                "trust record",
            ));
        }
        return Ok(trust);
    }
    if recorded != PackageTrust::DevUnsigned || auth.unsigned_dev_space.is_none() {
        return Err(PluginError::new(
            PluginErrorKind::PublisherUnauthorized,
            "unsigned package",
        ));
    }
    Ok(PackageTrust::DevUnsigned)
}

fn verify_signature(
    auth: &InstallAuthorization,
    publisher: &str,
    signature: &[u8],
    payload: &[u8],
) -> Result<PackageTrust, PluginError> {
    let key = auth
        .accepted_publishers
        .iter()
        .find(|key| key.publisher == publisher)
        .ok_or_else(|| PluginError::new(PluginErrorKind::PublisherUnauthorized, publisher))?;
    if key.verifying_key.len() != 32 || signature.len() != 64 {
        return Err(PluginError::new(
            PluginErrorKind::PublisherUnauthorized,
            "signature",
        ));
    }
    UnparsedPublicKey::new(&ED25519, &key.verifying_key)
        .verify(payload, signature)
        .map_err(|_| PluginError::new(PluginErrorKind::PublisherUnauthorized, "signature"))?;
    Ok(PackageTrust::AcceptedPublisher)
}

pub(crate) fn embedding_payload_bytes(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    payload_bytes(files)
}

fn payload_bytes(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut payload = Vec::new();
    for (path, bytes) in files {
        if path == SIGNATURE_FILE {
            continue;
        }
        payload.extend(path.as_bytes());
        payload.push(0);
        payload.extend(bytes);
        payload.push(0);
    }
    payload
}

fn payload_artifact_id(payload: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, payload);
    let mut id = String::from("pkg-");
    for byte in digest.as_ref() {
        id.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        id.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    id
}

fn read_package(package: &Path) -> Result<BTreeMap<String, Vec<u8>>, PluginError> {
    reject_symlink_path(package)?;
    let mut files = BTreeMap::new();
    read_tree(package, package, &mut files)?;
    if !files.contains_key("manifest.yaml") {
        return Err(PluginError::new(
            PluginErrorKind::UnknownField,
            "manifest.yaml",
        ));
    }
    Ok(files)
}

fn read_tree(
    root: &Path,
    dir: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), PluginError> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(dir).map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "package"))?
    {
        entries.push(entry.map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "package"))?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| PluginError::new(PluginErrorKind::PathEscape, "name"))?;
        if name == "." || name == ".." || name.contains('/') {
            return Err(PluginError::new(PluginErrorKind::PathEscape, name));
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, name))?;
        if meta.file_type().is_symlink() {
            return Err(PluginError::new(PluginErrorKind::SymlinkDenied, name));
        }
        if meta.is_dir() {
            read_tree(root, &path, files)?;
            continue;
        }
        if !meta.is_file() {
            return Err(PluginError::new(PluginErrorKind::PathEscape, name));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, name))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| PluginError::new(PluginErrorKind::PathEscape, name))?;
        if relative != "manifest.yaml" && relative != SIGNATURE_FILE && !safe_relative(relative) {
            return Err(PluginError::new(PluginErrorKind::PathEscape, relative));
        }
        let mut file = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| {
                if error.raw_os_error() == Some(libc::ELOOP) {
                    PluginError::new(PluginErrorKind::SymlinkDenied, relative)
                } else {
                    PluginError::new(PluginErrorKind::PathEscape, relative)
                }
            })?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, relative))?;
        if files.insert(relative.to_string(), bytes).is_some() {
            return Err(PluginError::new(PluginErrorKind::DuplicateField, relative));
        }
    }
    Ok(())
}

fn reject_symlink_path(path: &Path) -> Result<(), PluginError> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(PluginError::new(PluginErrorKind::PathEscape, "parent"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push("/"),
            Component::Normal(name) => current.push(name),
            Component::CurDir => return Err(PluginError::new(PluginErrorKind::PathEscape, "dot")),
            Component::ParentDir => {
                return Err(PluginError::new(PluginErrorKind::PathEscape, "parent"));
            }
            Component::Prefix(_) => {
                return Err(PluginError::new(PluginErrorKind::PathEscape, "prefix"));
            }
        }
        if current.as_os_str() == "/" {
            continue;
        }
        if !current.exists() {
            continue;
        }
        let meta = fs::symlink_metadata(&current)
            .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "path"))?;
        if meta.file_type().is_symlink() {
            return Err(PluginError::new(PluginErrorKind::SymlinkDenied, "path"));
        }
    }
    Ok(())
}

fn path_inside(root: &Path, candidate: &Path) -> Result<bool, PluginError> {
    reject_symlink_path(root)?;
    reject_symlink_path(candidate)?;
    let root =
        fs::canonicalize(root).map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "dev"))?;
    let candidate = fs::canonicalize(candidate)
        .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "package"))?;
    Ok(candidate.starts_with(&root) && candidate != root)
}

struct CapturedArtifact {
    files: BTreeMap<String, Vec<u8>>,
}

struct LedgerRecord {
    trust: PackageTrust,
    publisher: String,
    payload: Vec<u8>,
}

fn encode_ledger(trust: PackageTrust, publisher: &str, payload: &[u8]) -> Vec<u8> {
    let trust_text = match trust {
        PackageTrust::AcceptedPublisher => "accepted-publisher",
        PackageTrust::DevUnsigned => "dev-unsigned",
        PackageTrust::EmbeddingOwnedBuiltin => "embedding-owned-builtin",
    };
    let mut bytes = format!(
        "v1\ntrust={trust_text}\npublisher={publisher}\npayload_len={}\n",
        payload.len()
    )
    .into_bytes();
    bytes.extend_from_slice(payload);
    bytes
}

fn decode_ledger(bytes: &[u8]) -> Result<LedgerRecord, PluginError> {
    let header_end = bytes
        .iter()
        .enumerate()
        .take(512)
        .fold(0usize, |count, (index, byte)| {
            if count == 4 {
                count
            } else if *byte == b'\n' {
                count + 1
            } else if index > 256 {
                5
            } else {
                count
            }
        });
    if header_end != 4 {
        return Err(PluginError::new(PluginErrorKind::PathEscape, "ledger"));
    }
    let split = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(3)
        .map(|(index, _)| index + 1)
        .ok_or_else(|| PluginError::new(PluginErrorKind::PathEscape, "ledger"))?;
    let header = std::str::from_utf8(&bytes[..split])
        .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "ledger"))?;
    let mut lines = header.lines();
    if lines.next() != Some("v1") {
        return Err(PluginError::new(PluginErrorKind::PathEscape, "ledger"));
    }
    let trust = match lines.next() {
        Some("trust=accepted-publisher") => PackageTrust::AcceptedPublisher,
        Some("trust=dev-unsigned") => PackageTrust::DevUnsigned,
        Some("trust=embedding-owned-builtin") => PackageTrust::EmbeddingOwnedBuiltin,
        _ => {
            return Err(PluginError::new(
                PluginErrorKind::PublisherUnauthorized,
                "ledger trust",
            ));
        }
    };
    let publisher = lines
        .next()
        .and_then(|line| line.strip_prefix("publisher="))
        .ok_or_else(|| PluginError::new(PluginErrorKind::PathEscape, "ledger publisher"))?;
    let payload_len = lines
        .next()
        .and_then(|line| line.strip_prefix("payload_len="))
        .and_then(|text| text.parse::<usize>().ok())
        .ok_or_else(|| PluginError::new(PluginErrorKind::PathEscape, "ledger length"))?;
    let payload = bytes
        .get(split..split + payload_len)
        .ok_or_else(|| PluginError::new(PluginErrorKind::PathEscape, "ledger payload"))?;
    if split + payload_len != bytes.len() {
        return Err(PluginError::new(
            PluginErrorKind::PathEscape,
            "ledger trailer",
        ));
    }
    Ok(LedgerRecord {
        trust,
        publisher: publisher.to_string(),
        payload: payload.to_vec(),
    })
}

fn reject_artifact_id(artifact_id: &str) -> Result<(), PluginError> {
    let Some(hex) = artifact_id.strip_prefix("pkg-") else {
        return Err(PluginError::new(PluginErrorKind::PathEscape, "artifact"));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PluginError::new(PluginErrorKind::PathEscape, "artifact"));
    }
    Ok(())
}

fn open_dir_nofollow(path: &Path) -> Result<OwnedFd, PluginError> {
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                PluginError::new(PluginErrorKind::SymlinkDenied, "store")
            } else {
                PluginError::new(PluginErrorKind::PathEscape, "store")
            }
        })?;
    Ok(OwnedFd::from(file))
}

fn c_name(name: &str) -> Result<CString, PluginError> {
    if name.is_empty() || name.contains('/') || name.contains('\0') || name == "." || name == ".." {
        return Err(PluginError::new(PluginErrorKind::PathEscape, name));
    }
    CString::new(name).map_err(|_| PluginError::new(PluginErrorKind::PathEscape, name))
}

fn open_at(dir: &OwnedFd, name: &str, flags: i32) -> Result<OwnedFd, PluginError> {
    let c_name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o644,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(PluginError::new(PluginErrorKind::SymlinkDenied, name));
        }
        return Err(PluginError::new(PluginErrorKind::PathEscape, name));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_dir_at(dir: &OwnedFd, name: &str) -> Result<OwnedFd, PluginError> {
    open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)
}

fn open_file_at(dir: &OwnedFd, name: &str) -> Result<OwnedFd, PluginError> {
    let fd = open_at(dir, name, libc::O_RDONLY)?;
    if !is_regular_file(&fd)? {
        return Err(PluginError::new(PluginErrorKind::PathEscape, name));
    }
    Ok(fd)
}

fn is_regular_file(fd: &OwnedFd) -> Result<bool, PluginError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) };
    if rc != 0 {
        return Err(PluginError::new(PluginErrorKind::PathEscape, "stat"));
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFREG)
}

fn list_dir(dir: &OwnedFd) -> Result<Vec<String>, PluginError> {
    let proc = format!("/proc/self/fd/{}", dir.as_raw_fd());
    let mut names = Vec::new();
    for entry in fs::read_dir(&proc)
        .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "directory"))?
    {
        let entry =
            entry.map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "directory"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| PluginError::new(PluginErrorKind::PathEscape, "name"))?;
        if name == "." || name == ".." {
            continue;
        }
        names.push(name.to_string());
    }
    names.sort();
    Ok(names)
}

fn read_limited(fd: OwnedFd, limit: usize) -> Result<Vec<u8>, PluginError> {
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "read"))?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > limit {
            return Err(PluginError::new(
                PluginErrorKind::BudgetExceeded,
                "artifact file",
            ));
        }
        bytes.extend_from_slice(&buf[..read]);
    }
    Ok(bytes)
}

fn write_file_at(dir: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), PluginError> {
    if bytes.len() > MAX_CAPTURE_FILE {
        return Err(PluginError::new(PluginErrorKind::BudgetExceeded, name));
    }
    let fd = open_at(dir, name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, name))?;
    file.sync_all()
        .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, name))?;
    Ok(())
}

fn write_relative(dir: &OwnedFd, relative: &str, bytes: &[u8]) -> Result<(), PluginError> {
    if !safe_relative(relative) {
        return Err(PluginError::new(PluginErrorKind::PathEscape, relative));
    }
    let mut parts = relative.split('/').collect::<Vec<_>>();
    let file_name = parts
        .pop()
        .ok_or_else(|| PluginError::new(PluginErrorKind::PathEscape, relative))?;
    let mut current = dir
        .try_clone()
        .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, relative))?;
    for part in parts {
        if open_dir_at(&current, part).is_err() {
            mkdir_at(&current, part)?;
        }
        current = open_dir_at(&current, part)?;
    }
    write_file_at(&current, file_name, bytes)
}

fn mkdir_at(dir: &OwnedFd, name: &str) -> Result<(), PluginError> {
    let c_name = c_name(name)?;
    let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), c_name.as_ptr(), 0o755) };
    if rc != 0 {
        return Err(PluginError::new(PluginErrorKind::PathEscape, name));
    }
    Ok(())
}

fn rename_at(dir: &OwnedFd, from: &str, to: &str) -> Result<(), PluginError> {
    let from_name = c_name(from)?;
    let to_name = c_name(to)?;
    let rc = unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            from_name.as_ptr(),
            dir.as_raw_fd(),
            to_name.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(PluginError::new(PluginErrorKind::PathEscape, to));
    }
    Ok(())
}

fn sync_dir(dir: &OwnedFd) -> Result<(), PluginError> {
    let file = File::from(
        dir.try_clone()
            .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "sync"))?,
    );
    file.sync_all()
        .map_err(|_| PluginError::new(PluginErrorKind::PathEscape, "sync"))
}

fn remove_tree(parent: &OwnedFd, name: &str) -> Result<(), PluginError> {
    if let Ok(dir) = open_dir_at(parent, name) {
        for child in list_dir(&dir)? {
            remove_tree(&dir, &child)?;
        }
        unlink_at(parent, name, libc::AT_REMOVEDIR)?;
        return Ok(());
    }
    unlink_at(parent, name, 0)
}

fn unlink_at(dir: &OwnedFd, name: &str, flags: i32) -> Result<(), PluginError> {
    let c_name = c_name(name)?;
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), c_name.as_ptr(), flags) };
    if rc != 0 {
        return Err(PluginError::new(PluginErrorKind::PathEscape, name));
    }
    Ok(())
}

fn capture_sources(
    dir: &OwnedFd,
    prefix: &str,
    files: &mut BTreeMap<String, Vec<u8>>,
    total: &mut usize,
) -> Result<(), PluginError> {
    for name in list_dir(dir)? {
        if let Ok(child) = open_dir_at(dir, &name) {
            let next = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            capture_sources(&child, &next, files, total)?;
            continue;
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if !safe_relative(&relative) {
            return Err(PluginError::new(PluginErrorKind::PathEscape, relative));
        }
        let bytes = read_limited(open_file_at(dir, &name)?, MAX_CAPTURE_FILE)?;
        *total = total.saturating_add(bytes.len());
        if *total > MAX_CAPTURE_TOTAL || files.len() >= MAX_CAPTURE_FILES {
            return Err(PluginError::new(
                PluginErrorKind::BudgetExceeded,
                "artifact",
            ));
        }
        if files.insert(relative.clone(), bytes).is_some() {
            return Err(PluginError::new(PluginErrorKind::DuplicateField, relative));
        }
    }
    Ok(())
}
