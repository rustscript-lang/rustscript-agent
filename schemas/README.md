# Plugin contract schemas

These YAML files are the public structural contract for plugin manifests, effect entries, and graph locks. Native loads the same files. They are local and are not fetched.

`cargo run --example plugin_schema_sync -- --check` compares `schemas/canonical/*.json` with a sorted JSON projection of these YAML files. `cargo run --example plugin_schema_sync -- --write` regenerates that projection after a reviewed schema edit. The plugin schema test runs the same comparison and a drift rejection. Do not edit the JSON by hand.

The schemas express structure: required fields, enumerations, one public effect entry, safe relative paths, and the recovery/scope pairs that can be stated per effect kind. They do not express capability equality, semver satisfaction, dependency closure, or publisher authority. Those remain Native semantic checks. `replay` is not a v1 recovery. `checkpoint` is structural only for `workspace.fs.write`. `remote.write` and `process.spawn` cannot claim it.

A graph-lock edge records the caller entry, callee entry, alias, version requirement, resolved revision, and delegation scope. Provenance stays `direct`, `plugin`, or `library`. It is not collapsed to `delegated`.

`plugin-activation.schema.yaml` and `plugin-graph-ref.schema.yaml` are structural records for a stored activation pointer/history entry and a durable graph reference. A graph id is an opaque lock identity. These schemas do not grant host-catalog authority, rebuild a callable program, pin a live run, or claim hot reload. Reference owners are only `run` and `checkpoint`.

The joined generator also projects `schemas/v1/checkpoint.schema.yaml` to `schemas/canonical/checkpoint.schema.json`. That projection is structural drift coverage only. It does not validate checkpoint writes, permissions, or serialization; those stay on the Native checkpoint consumer.

`managed-checkpoint.schema.yaml` and `managed-restore.schema.yaml` describe the current managed maintenance DTOs and their nested named storage bodies. They use local `$defs` references, closed objects/enumerations and explicit boolean, null, optional and bounded collection rules. Native producers and strict parsers validate against these same schemas. Stateless coverage requires true absence assertions and empty state roots; artifact roots are unsupported. The independent `v1/checkpoint` contract is unchanged.

Managed receipts expose only the named public configuration projection. Safe provider execution options are retained in a separate private named record under the original validated option whitelist. Restore uses the frozen tree for guidance and the committed compaction summary plus exact retained history tail. Native authority, current admission limits and approvals are never serialized as reusable permission. Complete escaped transport, canonical original request proof, derived restore envelope and all repeated fixed SQL parameters share the existing aggregate metadata bound; an oversized complete request is rejected before enqueue.

`managed-effect.schema.yaml` keeps format `agent.managed-effect/v1`, `schemaVersion` 1 and the unchanged `ManagedPreparedRecord` shape. The optional `delegation` property was added additively: absent and explicit `null` both mean caller-only, a stateless caller→callee pin requires `intent`/`complete`, and a caller-only pin rejects a child proof. A new reader recovers every existing caller-only record; an older binary that denies unknown fields cannot read a child-bearing record, so deployment rollback after child records are written requires retaining the new reader (or a separately designed export/migration) and never silently discarding records. There is no v2 format, DDL migration, or old-row rewrite.
