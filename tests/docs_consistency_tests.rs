//! Documentation consistency guards (A9).
//!
//! These tests keep `docs/` truthful and prevent drift:
//!
//! - every `RUSTSCRIPT_AGENT_*` / `PD_EDGE_AGENT_*` variable the binaries
//!   read is documented in the canonical environment-variable table of
//!   `docs/configuration.md`, and every variable in that table is read by a
//!   binary — no advertised-but-nonexistent configuration;
//! - every `AgentGatewayConfig` field in `src/config.rs` is documented;
//! - the README links the canonical docs;
//! - relative markdown links in `README.md` and `docs/*.md` resolve.
//!
//! The environment-variable extraction is scoped to the canonical table
//! section of `docs/configuration.md` so the reserved (not yet implemented)
//! section can mention the future `RUSTSCRIPT_AGENT_TELEGRAM_…` family
//! without being mistaken for real configuration.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_relative(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

/// Extracts full `RUSTSCRIPT_AGENT_<NAME>` / `PD_EDGE_AGENT_<NAME>` tokens
/// (uppercase names) from a text. Bare prefix mentions such as
/// `RUSTSCRIPT_AGENT_*` produce an empty suffix and are ignored.
fn env_names_in(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for prefix in ["RUSTSCRIPT_AGENT_", "PD_EDGE_AGENT_"] {
        let mut rest = text;
        while let Some(start) = rest.find(prefix) {
            let tail = &rest[start + prefix.len()..];
            let end = tail
                .find(|character: char| {
                    !character.is_ascii_uppercase()
                        && !character.is_ascii_digit()
                        && character != '_'
                })
                .unwrap_or(tail.len());
            if !tail[..end].is_empty() {
                names.push(format!("{prefix}{}", &tail[..end]));
            }
            rest = &rest[start + 1..];
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Extracts the canonical environment-variable section of
/// `docs/configuration.md`: from the `## Environment variables (gateway
/// binary)` heading up to the next `## ` heading.
fn canonical_env_section() -> String {
    let configuration = read_relative("docs/configuration.md");
    let start = configuration
        .find("## Environment variables (gateway binary)")
        .unwrap_or_else(|| panic!("configuration.md must keep the canonical env table heading"));
    let rest = &configuration[start..];
    let end = rest[1..]
        .find("\n## ")
        .map(|offset| offset + 1)
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

fn config_struct_fields() -> Vec<String> {
    let source = read_relative("src/config.rs");
    let start = source
        .find("pub struct AgentGatewayConfig {")
        .unwrap_or_else(|| panic!("src/config.rs must define AgentGatewayConfig"));
    let rest = &source[start..];
    let end = rest.find("\n}").unwrap_or(rest.len());
    let mut fields = Vec::new();
    // Skip the struct declaration line itself (`pub struct … {`), then
    // collect every `pub <field>:` line inside the body.
    for line in rest[..end].lines().skip(1) {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("pub ")
            && let Some(name) = name.split(':').next()
        {
            fields.push(name.trim().to_string());
        }
    }
    fields.sort();
    fields.dedup();
    fields
}

/// Recursively collects every file under `src/`.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src directory") {
            let entry = entry.expect("read dir entry");
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&repo_root().join("src"), &mut files);
    files
}

#[test]
fn every_binary_env_var_is_documented() {
    let mut source_names = Vec::new();
    for file in source_files() {
        let text = std::fs::read_to_string(&file).expect("read source file");
        source_names.extend(env_names_in(&text));
    }
    source_names.sort();
    source_names.dedup();
    assert!(
        !source_names.is_empty(),
        "expected at least one RUSTSCRIPT_AGENT_/PD_EDGE_AGENT_ variable in src/"
    );
    let documented = env_names_in(&canonical_env_section());
    let missing = source_names
        .iter()
        .filter(|name| !documented.contains(name))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "binaries read configuration variables that docs/configuration.md does not document: {missing:?}"
    );
}

#[test]
fn no_documented_env_var_is_fictional() {
    let documented = env_names_in(&canonical_env_section());
    let mut source_names = Vec::new();
    for file in source_files() {
        let text = std::fs::read_to_string(&file).expect("read source file");
        source_names.extend(env_names_in(&text));
    }
    let invented = documented
        .iter()
        .filter(|name| !source_names.contains(name))
        .collect::<Vec<_>>();
    assert!(
        invented.is_empty(),
        "docs/configuration.md advertises configuration variables no binary reads: {invented:?}"
    );
}

#[test]
fn every_agent_gateway_config_field_is_documented() {
    let fields = config_struct_fields();
    assert!(
        fields.len() >= 10,
        "expected the documented AgentGatewayConfig field set, got {fields:?}"
    );
    let configuration = read_relative("docs/configuration.md");
    let start = configuration
        .find("## Native `AgentGatewayConfig` fields (library API)")
        .unwrap_or_else(|| panic!("configuration.md must keep the native fields section heading"));
    let section = &configuration[start..];
    let missing = fields
        .iter()
        .filter(|field| !section.contains(&format!("`{field}`")))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "AgentGatewayConfig fields missing from docs/configuration.md: {missing:?}"
    );
}

#[test]
fn readme_links_the_canonical_docs() {
    let readme = read_relative("README.md");
    for target in ["docs/configuration.md", "docs/deployment.md"] {
        assert!(
            readme.contains(&format!("]({target})")),
            "README.md must link {target}"
        );
    }
}

#[test]
fn relative_markdown_links_resolve() {
    let files = ["README.md", "docs/configuration.md", "docs/deployment.md"];
    let mut checked = 0;
    for file in files {
        let text = read_relative(file);
        let mut rest = text.as_str();
        while let Some(start) = rest.find("](") {
            let tail = &rest[start + 2..];
            let end = tail.find(')').expect("unterminated markdown link");
            let target = &tail[..end];
            rest = &tail[end + 1..];
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
                || target.starts_with('#')
            {
                continue;
            }
            let resolved = repo_root().join(file).parent().unwrap().join(target);
            assert!(
                resolved.exists(),
                "{file} links {target} which does not exist (resolved to {})",
                resolved.display()
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 3,
        "expected several relative links to check, got {checked}"
    );
}

/// Splits a markdown table row (`| a | b | … |`) into its trimmed cells
/// with inline-code backticks removed. Returns `None` for non-table lines.
fn table_cells(line: &str) -> Option<Vec<String>> {
    let line = line.trim();
    if !line.starts_with('|') || !line.ends_with('|') {
        return None;
    }
    let cells: Vec<String> = line
        .split('|')
        .map(|cell| cell.trim().replace('`', ""))
        .filter(|cell| !cell.is_empty())
        .collect();
    (!cells.is_empty()).then_some(cells)
}

/// Returns true when every inline-code span outside fenced blocks on the
/// line is closed: backtick runs must come in matched pairs of equal length
/// (`` `code` ``, `` ``code`` ``). Fenced code blocks (` ``` ` lines) and
/// their contents are skipped by the caller.
fn inline_code_closed(line: &str) -> bool {
    let mut runs: Vec<usize> = Vec::new();
    let mut chars = line.char_indices().peekable();
    while let Some((_, character)) = chars.next() {
        if character != '`' {
            continue;
        }
        let mut length = 1;
        while let Some((_, '`')) = chars.peek() {
            chars.next();
            length += 1;
        }
        match runs.last() {
            Some(&open) if open == length => {
                runs.pop();
            }
            _ => runs.push(length),
        }
    }
    runs.is_empty()
}

#[test]
fn inline_code_spans_in_docs_are_closed() {
    // An unclosed opening backtick makes the code span extend until the next
    // backtick in the document, rendering whole paragraphs as inline code on
    // GitHub. Every inline-code span in the two docs must be paired on its
    // line (tables and bullets are single lines); fenced code blocks and
    // their contents are skipped.
    let mut checked = 0;
    for file in ["docs/configuration.md", "docs/deployment.md"] {
        let text = read_relative(file);
        let mut in_fence = false;
        for (index, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence {
                continue;
            }
            assert!(
                inline_code_closed(line),
                "{file}:{} unclosed inline-code span in line: {line:?}",
                index + 1
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 200,
        "expected the full docs to be scanned, got {checked} lines"
    );
}

#[test]
fn authorization_bearer_placeholder_is_a_closed_inline_code_span() {
    // The `Authorization: Bearer <token>` placeholder must appear exactly as
    // a closed inline-code span (backtick immediately before and after the
    // placeholder) in both docs, matching the middleware's `Bearer ` strip
    // plus constant-time compare. Every mention of the token in the docs
    // must be that closed span.
    let token = "Authorization: Bearer ***";
    for file in ["docs/configuration.md", "docs/deployment.md"] {
        let text = read_relative(file);
        let closed_span = format!("`{token}`");
        assert!(
            text.contains(&closed_span),
            "{file} must contain the closed inline-code span {closed_span:?}"
        );
        assert_eq!(
            text.matches(&closed_span).count(),
            text.matches(token).count(),
            "{file}: every `{token}` mention must be the closed span {closed_span:?}"
        );
    }
}

#[test]
fn canonical_env_table_rows_are_well_formed_with_key_defaults() {
    // (variable, expected default cell, validation keyword the notes must
    // mention). The values mirror `src/config.rs` `Default` impl and
    // `src/bin/rustscript-agent-gateway.rs` env parsing:
    // exact "1" flag semantics, blank token rejection, port list validation,
    // and the deny-by-default policy.
    let key_rows: &[(&str, &str, &str)] = &[
        (
            "RUSTSCRIPT_AGENT_GATEWAY_ADDR",
            "127.0.0.1:8090",
            "fails startup",
        ),
        ("RUSTSCRIPT_AGENT_BEARER_TOKEN", "unset", "blank"),
        ("RUSTSCRIPT_AGENT_ALLOW_ANONYMOUS", "unset", "1"),
        ("RUSTSCRIPT_AGENT_ALLOW_SCHEMES", "https,wss", ""),
        (
            "RUSTSCRIPT_AGENT_ALLOW_PORTS",
            "empty (deny all)",
            "empty entries",
        ),
        ("RUSTSCRIPT_AGENT_ALLOW_PRIVATE_IPS", "unset (false)", "1"),
        ("RUSTSCRIPT_AGENT_STATE_DB", "unset (in-memory)", ""),
    ];
    let mut documented = Vec::new();
    for line in canonical_env_section().lines() {
        let Some(cells) = table_cells(line) else {
            continue;
        };
        let Some(variable) = cells.first() else {
            continue;
        };
        if !variable.starts_with("RUSTSCRIPT_AGENT_") {
            continue;
        }
        assert_eq!(
            cells.len(),
            5,
            "canonical env table row for {variable} must have 5 cells \
             (variable, alias, type, default, notes): {line}"
        );
        let expected_alias = format!("PD_EDGE_{}", variable.strip_prefix("RUSTSCRIPT_").unwrap());
        assert_eq!(
            cells[1], expected_alias,
            "alias column for {variable} must mirror the primary name"
        );
        for (key, default, note) in key_rows {
            if variable == *key {
                assert_eq!(cells[3], *default, "default cell for {key}");
                if !note.is_empty() {
                    assert!(
                        cells[4].contains(note),
                        "notes for {key} must keep the validation keyword {note:?}"
                    );
                }
            }
        }
        documented.push(variable.clone());
    }
    for (key, _, _) in key_rows {
        assert!(
            documented.contains(&key.to_string()),
            "canonical env table must document {key}"
        );
    }
}

#[test]
fn native_config_fields_and_key_defaults_are_documented() {
    let configuration = read_relative("docs/configuration.md");
    let start = configuration
        .find("## Native `AgentGatewayConfig` fields (library API)")
        .unwrap_or_else(|| panic!("configuration.md must keep the native fields section heading"));
    let section = &configuration[start..];
    let end = section[1..]
        .find("\n## ")
        .map(|offset| offset + 1)
        .unwrap_or(section.len());
    let section = &section[..end];

    let struct_fields = config_struct_fields();
    let mut documented = Vec::new();
    let mut defaults = std::collections::HashMap::new();
    for line in section.lines() {
        let Some(cells) = table_cells(line) else {
            continue;
        };
        let Some(field) = cells.first() else { continue };
        if field == "Field" || field == "---" {
            continue;
        }
        documented.push(field.clone());
        defaults.insert(field.clone(), cells.get(2).cloned());
    }
    let missing = struct_fields
        .iter()
        .filter(|field| !documented.contains(field))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "AgentGatewayConfig fields missing from docs/configuration.md: {missing:?}"
    );
    let fictional = documented
        .iter()
        .filter(|field| !struct_fields.contains(field))
        .collect::<Vec<_>>();
    assert!(
        fictional.is_empty(),
        "docs/configuration.md documents AgentGatewayConfig fields that do not exist: {fictional:?}"
    );
    // Key defaults mirror the `Default` impl in `src/config.rs`; a change on
    // either side must update the doc row and this table together.
    for (field, expected) in [
        ("max_concurrent_runs", "8"),
        ("run_timeout", "900 s"),
        ("max_body_bytes", "4 MiB"),
        ("max_events_per_run", "8192"),
        ("max_event_bytes", "32 KiB"),
        ("fuel", "Some(10_000_000)"),
    ] {
        assert_eq!(
            defaults.get(field).and_then(Option::as_deref),
            Some(expected),
            "default cell for native field {field} must stay {expected:?}"
        );
    }
}
