//! Root-confined coding file tools.
//!
//! Every user path is resolved through an immutable [`ConfinedFsRoot`]. The
//! implementation never canonicalizes a path and then reopens it, never shells
//! out, and never falls back to unrestricted `std::fs` on caller-supplied
//! paths.

use std::sync::Arc;
use std::time::Instant;

use rustscript_vm::{
    CancellationToken, ConfinedFileType, ConfinedFsError, ConfinedFsErrorKind, ConfinedFsLimits,
    ConfinedFsRoot, ConfinedPublicationState, EnumerationBudget, MAX_COMPONENT_BYTES,
    MAX_ENUM_ENTRIES, MAX_READ_BYTES, MAX_TEMP_ATTEMPTS, MAX_WRITE_BYTES,
};
use serde_json::{Value, json};

use super::artifacts::{ArtifactOwner, ArtifactStore};
use super::types::NativeToolExecutor;
use super::{
    ToolError, ToolResult, enforce_serialized_tool_result_cap, serialized_tool_result_len,
};
use crate::config::{FileToolConfig, MAX_FILE_TOOL_WALL_TIME};

const TEMP_PREFIX: &str = ".rustscript-agent-tmp-";

/// Request body for `read_file`.
#[derive(Clone, Debug)]
pub struct ReadFileRequest {
    pub path: String,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

impl ReadFileRequest {
    /// Reads `path` from line 1 with the configured default line budget.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            offset: None,
            limit: None,
        }
    }
}

/// Request body for `search_files`.
#[derive(Clone, Debug)]
pub struct SearchFilesRequest {
    pub pattern: String,
    pub path: Option<String>,
    pub target: Option<String>,
    pub file_glob: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl SearchFilesRequest {
    /// Searches workspace content for `pattern` from the retained root.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            path: None,
            target: None,
            file_glob: None,
            limit: None,
            offset: None,
        }
    }
}

/// Native coding file tools bound to one workspace root.
#[derive(Clone)]
pub struct FileTools {
    config: FileToolConfig,
    root: Arc<ConfinedFsRoot>,
    artifacts: Arc<ArtifactStore>,
    owner: Option<ArtifactOwner>,
    search_entered: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl FileTools {
    /// Validates `config`, retains the workspace root, and opens artifact storage.
    pub fn new(config: FileToolConfig) -> Result<Self, String> {
        config.validate()?;
        let artifacts = ArtifactStore::with_config(config.artifact_store.clone())
            .map_err(|error| error.message().to_string())?;
        Self::from_validated(config, Arc::new(artifacts))
    }

    /// Validates `config` and reuses a shared, already-opened artifact store.
    pub fn with_artifact_store(
        config: FileToolConfig,
        artifacts: Arc<ArtifactStore>,
    ) -> Result<Self, String> {
        config.validate()?;
        Self::from_validated(config, artifacts)
    }

    fn from_validated(
        config: FileToolConfig,
        artifacts: Arc<ArtifactStore>,
    ) -> Result<Self, String> {
        let limits = ConfinedFsLimits {
            max_read_bytes: config.max_read_bytes.min(MAX_READ_BYTES),
            max_write_bytes: config.max_write_bytes.min(MAX_WRITE_BYTES),
            max_entries: config.max_search_files.min(MAX_ENUM_ENTRIES),
            max_entry_name_bytes: MAX_COMPONENT_BYTES,
            max_temp_attempts: MAX_TEMP_ATTEMPTS.clamp(1, 32),
        };
        let root = ConfinedFsRoot::with_limits(&config.workspace_root, limits)
            .map_err(|error| error.message().to_string())?;
        Ok(Self {
            config,
            root: Arc::new(root),
            artifacts,
            owner: None,
            search_entered: None,
        })
    }

    /// Returns a clone scoped to `owner` for oversized-result publication.
    pub fn with_owner(&self, owner: ArtifactOwner) -> Self {
        Self {
            owner: Some(owner),
            ..self.clone()
        }
    }

    /// Test seam: `observer` runs when a later `search_files` walk begins.
    pub(crate) fn with_search_entered_observer(
        self,
        observer: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            search_entered: Some(observer),
            ..self
        }
    }

    /// Returns the service-owned artifact store.
    pub fn artifact_store(&self) -> &ArtifactStore {
        &self.artifacts
    }

    /// Returns a shared handle so process/terminal overflow can publish into the same store.
    pub fn artifact_store_arc(&self) -> Arc<ArtifactStore> {
        Arc::clone(&self.artifacts)
    }

    /// Executes a Task 1 native coding executor. Process tools are rejected.
    pub fn execute(&self, executor: &NativeToolExecutor, arguments: &Value) -> ToolResult {
        self.execute_with_controls(
            executor,
            arguments,
            &CancellationToken::new(),
            Instant::now() + MAX_FILE_TOOL_WALL_TIME,
        )
    }

    /// Executes a coding executor under the caller's cancellation token and deadline.
    pub fn execute_with_controls(
        &self,
        executor: &NativeToolExecutor,
        arguments: &Value,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        if let Some(result) = control_failure(cancellation, deadline, json!({})) {
            return result;
        }
        match executor {
            NativeToolExecutor::ReadFile => match parse_read_request(arguments) {
                Ok(request) => self.read_file_with_controls(request, cancellation, deadline),
                Err(message) => fail("invalid_arguments", message, json!({})),
            },
            NativeToolExecutor::SearchFiles => match parse_search_request(arguments) {
                Ok(request) => self.search_files_with_controls(request, cancellation, deadline),
                Err(message) => fail("invalid_arguments", message, json!({})),
            },
            NativeToolExecutor::WriteFile => {
                let Some(path) = arguments.get("path").and_then(Value::as_str) else {
                    return fail("invalid_arguments", "write_file requires path", json!({}));
                };
                let Some(content) = arguments.get("content").and_then(Value::as_str) else {
                    return fail(
                        "invalid_arguments",
                        "write_file requires content",
                        json!({}),
                    );
                };
                self.write_file_with_controls(path, content, cancellation, deadline)
            }
            NativeToolExecutor::Patch => {
                let Some(path) = arguments.get("path").and_then(Value::as_str) else {
                    return fail("invalid_arguments", "patch requires path", json!({}));
                };
                let Some(old_string) = arguments.get("old_string").and_then(Value::as_str) else {
                    return fail("invalid_arguments", "patch requires old_string", json!({}));
                };
                let Some(new_string) = arguments.get("new_string").and_then(Value::as_str) else {
                    return fail("invalid_arguments", "patch requires new_string", json!({}));
                };
                let replace_all = arguments
                    .get("replace_all")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.patch_with_controls(
                    path,
                    old_string,
                    new_string,
                    replace_all,
                    cancellation,
                    deadline,
                )
            }
            NativeToolExecutor::Terminal
            | NativeToolExecutor::Process
            | NativeToolExecutor::Placeholder(_) => fail(
                "unsupported_executor",
                "file tools do not execute process slots",
                json!({}),
            ),
        }
    }

    /// Reads a UTF-8 workspace file with optional 1-based line windowing.
    pub fn read_file(&self, request: ReadFileRequest) -> ToolResult {
        self.read_file_with_controls(
            request,
            &CancellationToken::new(),
            Instant::now() + MAX_FILE_TOOL_WALL_TIME,
        )
    }

    /// Reads a workspace file under the caller's cancellation token and deadline.
    pub fn read_file_with_controls(
        &self,
        request: ReadFileRequest,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        if let Some(result) = control_failure(cancellation, deadline, json!({})) {
            return result;
        }
        if request.offset == Some(0) {
            return fail(
                "invalid_offset",
                "read_file offset is 1-based",
                json!({ "offset": 0 }),
            );
        }
        let bytes = match self.root.read_file(&request.path) {
            Ok(bytes) => bytes,
            Err(error) => return map_fs_error(error, json!({})),
        };
        if let Some(result) = control_failure(cancellation, deadline, json!({})) {
            return result;
        }
        if bytes.contains(&0) {
            return fail("binary_file", "file contains binary content", json!({}));
        }
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                return fail("invalid_utf8", "file is not valid UTF-8", json!({}));
            }
        };
        let offset = request.offset.unwrap_or(1);
        let limit = request
            .limit
            .unwrap_or(self.config.max_read_lines)
            .min(self.config.max_read_lines);
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let skip = offset.saturating_sub(1);
        let window: Vec<&str> = if skip >= lines.len() {
            Vec::new()
        } else {
            lines.iter().copied().skip(skip).take(limit).collect()
        };
        let content = window.concat();
        let data = json!({
            "offset": offset as u64,
            "line_count": window.len() as u64,
        });
        self.finalize(success(content, data, false, Vec::new()))
    }

    /// Traverses the workspace with hard caps and a wall-clock deadline.
    pub fn search_files(&self, request: SearchFilesRequest) -> ToolResult {
        self.search_files_with_controls(
            request,
            &CancellationToken::new(),
            Instant::now() + MAX_FILE_TOOL_WALL_TIME,
        )
    }

    /// Searches the workspace under the caller's cancellation token and deadline.
    pub fn search_files_with_controls(
        &self,
        request: SearchFilesRequest,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        if let Some(result) = control_failure(cancellation, deadline, json!({})) {
            return result;
        }
        if request.pattern.is_empty() {
            return fail(
                "invalid_arguments",
                "search_files requires a pattern",
                json!({}),
            );
        }
        if let Some(observer) = &self.search_entered {
            observer();
        }
        let target_files = matches!(request.target.as_deref(), Some("files"));
        let start = request.path.as_deref().unwrap_or("");
        let search_budget = Instant::now() + self.config.max_search_wall_time;
        let mut state = SearchState::new();
        let controls = SearchWalkControls {
            cancel: cancellation,
            caller_deadline: deadline,
            search_budget,
        };
        if observe_search_controls(&controls, &mut state) {
            // Caller cancel/deadline or search wall-time already recorded.
        } else if let Err(error) =
            self.walk_search(start, 0, &request, target_files, &controls, &mut state)
        {
            return map_fs_error(error, json!({}));
        }
        if let Some((code, message)) = state.control {
            return fail(code, message, json!({}));
        }
        state.lines.sort();
        let offset = request.offset.unwrap_or(0);
        let limit = request
            .limit
            .unwrap_or(self.config.max_search_matches)
            .min(self.config.max_search_matches);
        let files_visited = state.files_visited as u64;
        let dirs_visited = state.dirs_visited as u64;
        let truncated = state.truncated;
        let selected: Vec<String> = state.lines.into_iter().skip(offset).take(limit).collect();
        let content = selected.join("\n");
        self.finalize(success(
            content,
            json!({
                "match_count": selected.len() as u64,
                "files_visited": files_visited,
                "dirs_visited": dirs_visited,
            }),
            truncated,
            Vec::new(),
        ))
    }

    /// Atomically publishes UTF-8 content to a workspace path.
    pub fn write_file(&self, path: &str, content: &str) -> ToolResult {
        self.write_file_with_controls(
            path,
            content,
            &CancellationToken::new(),
            Instant::now() + MAX_FILE_TOOL_WALL_TIME,
        )
    }

    /// Writes a workspace file under the caller's cancellation token and deadline.
    pub fn write_file_with_controls(
        &self,
        path: &str,
        content: &str,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        if let Some(result) = control_failure(
            cancellation,
            deadline,
            json!({ "publication": "not_published" }),
        ) {
            return result;
        }
        if content.len() > self.config.max_write_bytes {
            return fail(
                "write_too_large",
                "write exceeds the configured byte budget",
                json!({ "publication": "not_published" }),
            );
        }
        match self.publish(path, content.as_bytes()) {
            Ok((durable, staging_cleaned)) => self.finalize(published_result(
                format!("wrote {} bytes", content.len()),
                durable,
                staging_cleaned,
                content.len(),
            )),
            Err(error) => map_write_error(error),
        }
    }

    /// Replaces a unique match, or every match when `replace_all` is set.
    pub fn patch(&self, path: &str, old: &str, new: &str, replace_all: bool) -> ToolResult {
        self.patch_with_controls(
            path,
            old,
            new,
            replace_all,
            &CancellationToken::new(),
            Instant::now() + MAX_FILE_TOOL_WALL_TIME,
        )
    }

    /// Patches a workspace file under the caller's cancellation token and deadline.
    pub fn patch_with_controls(
        &self,
        path: &str,
        old: &str,
        new: &str,
        replace_all: bool,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> ToolResult {
        if let Some(result) = control_failure(
            cancellation,
            deadline,
            json!({ "publication": "not_published" }),
        ) {
            return result;
        }
        if old.is_empty() {
            return fail(
                "invalid_arguments",
                "patch old_string must be non-empty",
                json!({ "publication": "not_published" }),
            );
        }
        let bytes = match self.root.read_file(path) {
            Ok(bytes) => bytes,
            Err(error) => return map_write_error(error),
        };
        if bytes.len() > self.config.max_patch_bytes {
            return fail(
                "patch_too_large",
                "source exceeds the configured patch budget",
                json!({ "publication": "not_published" }),
            );
        }
        if bytes.contains(&0) {
            return fail(
                "binary_file",
                "file contains binary content",
                json!({ "publication": "not_published" }),
            );
        }
        let source = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                return fail(
                    "invalid_utf8",
                    "file is not valid UTF-8",
                    json!({ "publication": "not_published" }),
                );
            }
        };
        let matches = source.matches(old).count();
        if matches == 0 {
            return fail(
                "patch_no_match",
                "old_string was not found",
                json!({ "publication": "not_published" }),
            );
        }
        if matches > 1 && !replace_all {
            return fail(
                "patch_multiple_matches",
                "old_string matches more than once",
                json!({ "publication": "not_published", "matches": matches as u64 }),
            );
        }
        let replacements = if replace_all { matches } else { 1 };
        let updated = if replace_all {
            source.replace(old, new)
        } else {
            source.replacen(old, new, 1)
        };
        if updated.len() > self.config.max_patch_bytes {
            return fail(
                "patch_too_large",
                "result exceeds the configured patch budget",
                json!({ "publication": "not_published" }),
            );
        }
        if let Some(result) = control_failure(
            cancellation,
            deadline,
            json!({ "publication": "not_published" }),
        ) {
            return result;
        }
        match self.publish(path, updated.as_bytes()) {
            Ok((durable, staging_cleaned)) => {
                let preview =
                    bounded_diff(path, &source, &updated, self.config.max_patch_preview_bytes);
                let mut result = published_result(preview, durable, staging_cleaned, updated.len());
                result.data["replacements"] = json!(replacements as u64);
                self.finalize(result)
            }
            Err(error) => map_write_error(error),
        }
    }

    #[allow(clippy::result_large_err)]
    fn publish(&self, path: &str, data: &[u8]) -> Result<(bool, bool), ConfinedFsError> {
        let (parent, leaf) = split_publication_target(path);
        let mut temp = self.root.create_temp(parent, TEMP_PREFIX)?;
        temp.write_all(data)?;
        temp.flush()?;
        temp.sync_all()?;
        match self.root.atomic_replace(temp, leaf) {
            Ok(publication) => Ok((publication.is_durable(), publication.staging_cleaned())),
            Err(error) => match error.publication_state() {
                ConfinedPublicationState::Published {
                    durable,
                    staging_cleaned,
                } => Ok((durable, staging_cleaned)),
                _ => Err(error),
            },
        }
    }

    #[allow(clippy::result_large_err)]
    fn walk_search(
        &self,
        dir: &str,
        depth: usize,
        request: &SearchFilesRequest,
        target_files: bool,
        controls: &SearchWalkControls<'_>,
        state: &mut SearchState,
    ) -> Result<(), ConfinedFsError> {
        state.dirs_visited = state.dirs_visited.saturating_add(1);
        if observe_search_controls(controls, state) {
            return Ok(());
        }
        if state.stop {
            return Ok(());
        }
        if state.lines.len() >= self.config.max_search_matches {
            state.truncated = true;
            state.stop = true;
            return Ok(());
        }
        if state.files_visited >= self.config.max_search_files {
            state.truncated = true;
            state.stop = true;
            return Ok(());
        }
        let remaining_files = self
            .config
            .max_search_files
            .saturating_sub(state.files_visited);
        let budget = EnumerationBudget {
            max_entries: remaining_files
                .min(self.config.max_search_files)
                .min(MAX_ENUM_ENTRIES),
            max_name_bytes: MAX_COMPONENT_BYTES,
        };
        let mut entries = match self.root.enumerate_with_budget(dir, budget) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ConfinedFsErrorKind::BudgetExceeded => {
                state.truncated = true;
                state.stop = true;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        entries.sort_by(|left, right| left.name().cmp(right.name()));
        for entry in entries {
            if observe_search_controls(controls, state) {
                return Ok(());
            }
            if state.stop {
                return Ok(());
            }
            let Some(name) = entry.name_os().to_str() else {
                continue;
            };
            if name.starts_with(TEMP_PREFIX) {
                continue;
            }
            let child = join_rel(dir, name);
            match entry.metadata().file_type() {
                ConfinedFileType::Directory => {
                    if depth + 1 > self.config.max_search_depth {
                        state.truncated = true;
                        continue;
                    }
                    self.walk_search(&child, depth + 1, request, target_files, controls, state)?;
                    if state.stop {
                        return Ok(());
                    }
                }
                ConfinedFileType::File => {
                    if state.files_visited >= self.config.max_search_files {
                        state.truncated = true;
                        state.stop = true;
                        return Ok(());
                    }
                    state.files_visited += 1;
                    if request
                        .file_glob
                        .as_deref()
                        .is_some_and(|glob| !glob_match(glob, name) && !glob_match(glob, &child))
                    {
                        continue;
                    }
                    if target_files {
                        if glob_match(&request.pattern, name)
                            || glob_match(&request.pattern, &child)
                        {
                            self.push_match(state, child);
                            if state.stop {
                                return Ok(());
                            }
                        }
                        continue;
                    }
                    let size = usize::try_from(entry.metadata().len()).unwrap_or(usize::MAX);
                    if state.scanned_bytes.saturating_add(size)
                        > self.config.max_search_scanned_bytes
                    {
                        state.truncated = true;
                        state.stop = true;
                        return Ok(());
                    }
                    if observe_search_controls(controls, state) {
                        return Ok(());
                    }
                    let bytes = match self.root.read_file(&child) {
                        Ok(bytes) => bytes,
                        Err(error) if is_skip_search_error(&error) => continue,
                        Err(error) => return Err(error),
                    };
                    state.scanned_bytes = state.scanned_bytes.saturating_add(bytes.len());
                    if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
                        continue;
                    }
                    let text = String::from_utf8(bytes).unwrap_or_default();
                    for (index, line) in text.split_inclusive('\n').enumerate() {
                        if observe_search_controls(controls, state) {
                            return Ok(());
                        }
                        if line.contains(&request.pattern) {
                            let trimmed = line.trim_end_matches(['\n', '\r']);
                            self.push_match(state, format!("{}:{}:{trimmed}", child, index + 1));
                            if state.stop
                                || state.truncated
                                || state.lines.len() >= self.config.max_search_matches
                            {
                                if state.control.is_none() {
                                    state.truncated = true;
                                    state.stop = true;
                                }
                                return Ok(());
                            }
                        }
                    }
                }
                ConfinedFileType::Symlink | ConfinedFileType::Other => {}
            }
        }
        Ok(())
    }

    fn push_match(&self, state: &mut SearchState, line: String) {
        let extra = if state.lines.is_empty() {
            line.len()
        } else {
            line.len() + 1
        };
        if state.output_bytes.saturating_add(extra) > self.config.max_search_output_bytes {
            state.truncated = true;
            state.stop = true;
            return;
        }
        state.output_bytes += extra;
        state.lines.push(line);
    }

    fn finalize(&self, mut result: ToolResult) -> ToolResult {
        let cap = self.config.max_output_bytes;
        if serialized_tool_result_len(&result) <= cap {
            return result;
        }
        if let Some(owner) = self.owner.as_ref() {
            match self.artifacts.put(owner, result.content.as_bytes()) {
                Ok(handle) => {
                    let bytes = result.content.len();
                    result.content = artifact_summary(&handle.id, bytes, cap);
                    result.truncated = true;
                    result.artifacts = vec![handle.id];
                }
                Err(error) => {
                    result = fail(error.code(), error.message(), result.data);
                }
            }
        }
        enforce_serialized_tool_result_cap(&mut result, cap);
        result
    }
}

struct SearchWalkControls<'a> {
    cancel: &'a CancellationToken,
    caller_deadline: Instant,
    search_budget: Instant,
}

struct SearchState {
    files_visited: usize,
    dirs_visited: usize,
    scanned_bytes: usize,
    output_bytes: usize,
    lines: Vec<String>,
    truncated: bool,
    stop: bool,
    control: Option<(&'static str, &'static str)>,
}

impl SearchState {
    fn new() -> Self {
        Self {
            files_visited: 0,
            dirs_visited: 0,
            scanned_bytes: 0,
            output_bytes: 0,
            lines: Vec::new(),
            truncated: false,
            stop: false,
            control: None,
        }
    }
}

fn control_failure(
    cancel: &CancellationToken,
    deadline: Instant,
    data: Value,
) -> Option<ToolResult> {
    if cancel.is_cancelled() {
        return Some(fail("cancelled", "tool execution was cancelled", data));
    }
    if Instant::now() >= deadline {
        return Some(fail("deadline_elapsed", "tool deadline elapsed", data));
    }
    None
}

fn observe_search_controls(controls: &SearchWalkControls<'_>, state: &mut SearchState) -> bool {
    if state.control.is_some() {
        state.stop = true;
        return true;
    }
    if controls.cancel.is_cancelled() {
        state.control = Some(("cancelled", "tool execution was cancelled"));
        state.stop = true;
        return true;
    }
    if Instant::now() >= controls.caller_deadline {
        state.control = Some(("deadline_elapsed", "tool deadline elapsed"));
        state.stop = true;
        return true;
    }
    if Instant::now() >= controls.search_budget {
        state.truncated = true;
        state.stop = true;
        return true;
    }
    false
}

fn split_publication_target(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((parent, leaf)) => (parent, leaf),
        None => ("", path),
    }
}

fn join_rel(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    glob_rec(pattern.as_bytes(), text.as_bytes())
}

fn glob_rec(pat: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_p = None;
    let mut star_t = 0;
    while ti < text.len() {
        if pi < pat.len() && pat[pi] != b'*' && (pat[pi] == b'?' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_p = Some(pi);
            pi += 1;
            star_t = ti;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

fn bounded_diff(path: &str, before: &str, after: &str, max_bytes: usize) -> String {
    let mut preview = format!("diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n");
    if preview.len() > max_bytes {
        return finish_truncated(preview, max_bytes);
    }
    let before_lines: Vec<&str> = before.split_inclusive('\n').collect();
    let after_lines: Vec<&str> = after.split_inclusive('\n').collect();
    for (old, new) in before_lines.iter().zip(after_lines.iter()) {
        if old != new && !push_diff_line(&mut preview, '-', old, max_bytes) {
            return preview;
        }
        if old != new && !push_diff_line(&mut preview, '+', new, max_bytes) {
            return preview;
        }
    }
    if before_lines.len() < after_lines.len() {
        for line in &after_lines[before_lines.len()..] {
            if !push_diff_line(&mut preview, '+', line, max_bytes) {
                return preview;
            }
        }
    } else if after_lines.len() < before_lines.len() {
        for line in &before_lines[after_lines.len()..] {
            if !push_diff_line(&mut preview, '-', line, max_bytes) {
                return preview;
            }
        }
    }
    if preview.len() > max_bytes {
        return finish_truncated(preview, max_bytes);
    }
    preview
}

const TRUNCATION_MARKER: &str = "…";

fn push_diff_line(preview: &mut String, marker: char, line: &str, max_bytes: usize) -> bool {
    preview.push(marker);
    preview.push_str(line.trim_end_matches('\n'));
    preview.push('\n');
    if preview.len() <= max_bytes {
        return true;
    }
    *preview = finish_truncated(std::mem::take(preview), max_bytes);
    false
}

fn finish_truncated(preview: String, max_bytes: usize) -> String {
    if preview.len() <= max_bytes {
        return preview;
    }
    if max_bytes < TRUNCATION_MARKER.len() {
        return utf8_prefix(&preview, max_bytes).to_string();
    }
    let mut truncated = utf8_prefix(&preview, max_bytes - TRUNCATION_MARKER.len()).to_string();
    truncated.push_str(TRUNCATION_MARKER);
    truncated
}

fn utf8_prefix(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn artifact_summary(id: &str, bytes: usize, max_output_bytes: usize) -> String {
    let candidates = [
        format!("artifact {id} ({bytes} bytes)"),
        format!("artifact {id}"),
        "artifact".to_string(),
    ];
    candidates
        .into_iter()
        .find(|summary| summary.len() <= max_output_bytes)
        .unwrap_or_else(|| utf8_prefix("artifact", max_output_bytes).to_string())
}

fn success(content: String, data: Value, truncated: bool, artifacts: Vec<String>) -> ToolResult {
    ToolResult {
        ok: true,
        content,
        data,
        error: None,
        truncated,
        artifacts,
    }
}

fn fail(code: &str, message: &str, data: Value) -> ToolResult {
    ToolResult {
        ok: false,
        content: String::new(),
        data,
        error: Some(ToolError {
            code: code.to_string(),
            message: message.to_string(),
        }),
        truncated: false,
        artifacts: Vec::new(),
    }
}

fn published_result(
    content: String,
    durable: bool,
    staging_cleaned: bool,
    bytes: usize,
) -> ToolResult {
    success(
        content,
        json!({
            "publication": "published",
            "durable": durable,
            "staging_cleaned": staging_cleaned,
            "bytes": bytes as u64,
        }),
        false,
        Vec::new(),
    )
}

fn map_write_error(error: ConfinedFsError) -> ToolResult {
    match error.publication_state() {
        ConfinedPublicationState::Published {
            durable,
            staging_cleaned,
        } => success(
            "wrote file".to_string(),
            json!({
                "publication": "published",
                "durable": durable,
                "staging_cleaned": staging_cleaned,
            }),
            false,
            Vec::new(),
        ),
        ConfinedPublicationState::Indeterminate { .. } => fail(
            "publication_indeterminate",
            "write publication could not be classified",
            json!({ "publication": "indeterminate" }),
        ),
        ConfinedPublicationState::NotPublished => {
            let mut result = map_fs_error(error, json!({ "publication": "not_published" }));
            if let Some(error) = result
                .error
                .as_mut()
                .filter(|error| error.code == "wrong_type")
            {
                error.code = "path_denied".to_string();
            }
            result
        }
    }
}

fn map_fs_error(error: ConfinedFsError, data: Value) -> ToolResult {
    let code = match error.kind() {
        ConfinedFsErrorKind::InvalidPath
        | ConfinedFsErrorKind::EmptyPath
        | ConfinedFsErrorKind::AbsolutePath
        | ConfinedFsErrorKind::ParentTraversal
        | ConfinedFsErrorKind::NulByte
        | ConfinedFsErrorKind::PathTooLong
        | ConfinedFsErrorKind::ComponentTooLong
        | ConfinedFsErrorKind::InvalidSeparator
        | ConfinedFsErrorKind::PathPrefix
        | ConfinedFsErrorKind::SymlinkDenied
        | ConfinedFsErrorKind::HardlinkDenied => "path_denied",
        ConfinedFsErrorKind::NotFound => "not_found",
        ConfinedFsErrorKind::PermissionDenied => "permission_denied",
        ConfinedFsErrorKind::WrongType => "wrong_type",
        ConfinedFsErrorKind::BudgetExceeded => "budget_exceeded",
        ConfinedFsErrorKind::InvalidData => "invalid_utf8",
        ConfinedFsErrorKind::InvalidConfiguration => "invalid_config",
        _ => "io_error",
    };
    fail(code, error.message(), data)
}

fn is_skip_search_error(error: &ConfinedFsError) -> bool {
    matches!(
        error.kind(),
        ConfinedFsErrorKind::SymlinkDenied
            | ConfinedFsErrorKind::HardlinkDenied
            | ConfinedFsErrorKind::WrongType
            | ConfinedFsErrorKind::NotFound
            | ConfinedFsErrorKind::PermissionDenied
            | ConfinedFsErrorKind::BudgetExceeded
            | ConfinedFsErrorKind::InvalidData
    )
}

fn parse_read_request(arguments: &Value) -> Result<ReadFileRequest, &'static str> {
    let Some(path) = arguments.get("path").and_then(Value::as_str) else {
        return Err("read_file requires path");
    };
    Ok(ReadFileRequest {
        path: path.to_string(),
        offset: parse_optional_usize(arguments, "offset")?,
        limit: parse_optional_usize(arguments, "limit")?,
    })
}

fn parse_search_request(arguments: &Value) -> Result<SearchFilesRequest, &'static str> {
    let Some(pattern) = arguments.get("pattern").and_then(Value::as_str) else {
        return Err("search_files requires pattern");
    };
    Ok(SearchFilesRequest {
        pattern: pattern.to_string(),
        path: arguments
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_string),
        target: arguments
            .get("target")
            .and_then(Value::as_str)
            .map(str::to_string),
        file_glob: arguments
            .get("file_glob")
            .and_then(Value::as_str)
            .map(str::to_string),
        limit: parse_optional_usize(arguments, "limit")?,
        offset: parse_optional_usize(arguments, "offset")?,
    })
}

fn parse_optional_usize(arguments: &Value, key: &str) -> Result<Option<usize>, &'static str> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(number) = value.as_u64() else {
        return Err("numeric argument is invalid");
    };
    Ok(Some(usize::try_from(number).unwrap_or(usize::MAX)))
}
