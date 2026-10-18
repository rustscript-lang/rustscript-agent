# Plugin contract schemas

These YAML files are the public structural contract for plugin manifests, effect entries, and graph locks. Native loads the same files. They are local and are not fetched.

`cargo run --example plugin_schema_sync -- --check` compares `schemas/canonical/*.json` with a sorted JSON projection of these YAML files. `cargo run --example plugin_schema_sync -- --write` regenerates that projection after a reviewed schema edit. The plugin schema test runs the same comparison and a drift rejection. Do not edit the JSON by hand.

The schemas express structure: required fields, enumerations, one public effect entry, safe relative paths, and the recovery/scope pairs that can be stated per effect kind. They do not express capability equality, semver satisfaction, dependency closure, or publisher authority. Those remain Native semantic checks. `replay` is not a v1 recovery. `checkpoint` is structural only for `workspace.fs.write`. `remote.write` and `process.spawn` cannot claim it.

A graph-lock edge records the caller entry, callee entry, alias, version requirement, resolved revision, and delegation scope. Provenance stays `direct`, `plugin`, or `library`. It is not collapsed to `delegated`.

`plugin-activation.schema.yaml` and `plugin-graph-ref.schema.yaml` are structural records for a stored activation pointer/history entry and a durable graph reference. A graph id is an opaque lock identity. These schemas do not grant host-catalog authority, rebuild a callable program, pin a live run, or claim hot reload. Reference owners are only `run` and `checkpoint`.

The joined generator also projects `schemas/v1/checkpoint.schema.yaml` to `schemas/canonical/checkpoint.schema.json`. That projection is structural drift coverage only. It does not validate checkpoint writes, permissions, or serialization; those stay on the Native checkpoint consumer.
