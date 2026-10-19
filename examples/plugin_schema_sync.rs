//! Regenerate or check canonical JSON projections of the public YAML schemas.
//!
//! The YAML files are the contract. This tool does not invent a second schema
//! and does not fetch anything. `--check` fails if `schemas/canonical` drifted.

fn main() {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "--check".to_string());
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas/canonical");
    match command.as_str() {
        "--check" => match rustscript_agent::plugins::schema_snapshot_drift(&dir) {
            Ok(()) => println!("schema snapshots match {}", dir.display()),
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        },
        "--write" => {
            let docs =
                rustscript_agent::plugins::canonical_schema_documents().expect("bundled schemas");
            std::fs::create_dir_all(&dir).expect("canonical dir");
            for (name, json) in docs {
                std::fs::write(dir.join(name), json).expect(name);
            }
            println!("wrote {}", dir.display());
        }
        _ => {
            eprintln!("usage: plugin_schema_sync --check|--write");
            std::process::exit(2);
        }
    }
}
