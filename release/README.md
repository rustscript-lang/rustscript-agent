# Release asset classification

These sorted inventories are the reviewed allowlist for the Linux x86_64 GNU archive. Packaging reads only the production inventories; support inventories make repository-wide classification drift fail tests without shipping fixtures or developer helpers.

- `rss-production.txt`: production `rss/**/*.rss`; each source keeps its path below `share/rustscript-agent/rss/`.
- `rss-support.txt`: RSS fixtures and harness entry points excluded from the release.
- `schema-production.txt`: `source<TAB>archive destination` for the 10 production YAML schemas.
- `schema-support.txt`: canonical JSON and schema-maintenance documentation excluded from the release.
- `example-production.txt`: `source<TAB>archive destination` for the approved configuration/auth examples and `http_get.rss`.
- `example-support.txt`: example-maintenance source excluded from the release.

Tests require each tracked RSS, schema, and example candidate to appear in exactly one applicable production or support inventory. New assets remain unshipped until reviewed and classified. Production RSS imports must resolve entirely inside the production RSS inventory.
