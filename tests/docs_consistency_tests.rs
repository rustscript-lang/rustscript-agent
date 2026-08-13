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
