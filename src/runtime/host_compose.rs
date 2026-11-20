//! Deterministic host-module composition for the agent runtime.
//!
//! Standard HTTP/SQLite/json/bytes schemas come from frozen core catalogs.
//! Agent modules contribute descriptor-owned schemas and adapters.

use std::sync::Arc;

use rustscript_vm::{
    CallOutcome, HostAdapterDescriptor, HostApiBuilder, HostApiCatalog, HostBindingDescriptor,
    HostBindingKind, HostFunctionDescriptor, HostFunctionSchema, HostModuleDescriptor,
    HostTypeSchema, Value, Vm, VmResult, standard_host_catalog, standard_host_modules,
};

/// Slots that carry one open JSON payload as **serialized text**.
///
/// Every entry is (`function_name`, `slot`) where slot is a parameter label or
/// `return.<field>` of the declared named struct. The audit resolves the entry
/// to that exact field and requires it to be `String` itself — a struct that
/// merely *contains* some string field does not satisfy the promise. The guest
/// never decodes these; the host adapter parses or serializes them.
#[allow(dead_code)] // read by the boundary audit
pub const OPEN_JSON_TEXT_SLOTS: &[(&str, &str)] = &[
    // Parsed-object bodies cross as serialized text in `value`.
    ("agent::parse_json_object", "return.value"),
    // The provider request is serialized by the guest through
    // `agent::json_text`; the host parses it, bounds it (4 MiB) and requires an
    // object before it reaches the provider.
    ("agent::provider_call", "request"),
    // Provider bodies: open request/response JSON over the provider bridge.
    ("agent::provider_call", "return.error"),
    ("agent::provider_call", "return.response"),
    // Approval storage: the durable payload is provider/tool defined JSON, so
    // it crosses as text and the host parses it.
    ("agent::approval_storage", "payload"),
    // The durable transcript handed to the context refresh is open JSON.
    ("agent::refresh_context", "context"),
    // Guest→host serialization bridge.
    ("agent::json_text", "return.text"),
    // Tool lifecycle metadata: the host parses the text into prepare metadata.
    ("agent_runtime::tool_prepare", "metadata"),
    ("agent_runtime::tool_replay", "metadata"),
    ("agent_runtime::approval_attest", "metadata"),
    // The guest serializes its canonical tool result; the host parses it.
    ("agent_runtime::tool_commit", "result"),
    // Replayed/committed canonical results come back as text.
    ("agent_runtime::tool_prepare", "return.result"),
    ("agent_runtime::tool_replay", "return.result"),
    ("agent_runtime::approval_attest", "return.result"),
    ("agent_runtime::tool_commit", "return.result"),
    // Artifact metadata is durable, plugin/provider defined JSON.
    ("cap::artifact_put", "metadata"),
    ("cap::artifact_put_result", "metadata"),
    ("cap::artifact_put", "return.metadata"),
    ("cap::artifact_put_result", "return.metadata"),
    ("cap::artifact_reference", "return.metadata"),
];

/// Parameter slots that accept arbitrary native JSON.
///
/// This is not a quarantine: a function that receives a provider- or
/// plugin-defined body has no concrete schema to declare, and this pin admits
/// no guest-side JSON serializer, so a dynamic *input* is the only way to pass
/// such a value in. Three rules keep the list honest: the resolved slot must be
/// exactly `Unknown`, it must be a parameter (a dynamic **return** is never
/// accepted — the compiler rejects those outright), and the host adapter that
/// owns it must do its own bounded validation.
#[allow(dead_code)] // read by the boundary audit
pub const OPEN_JSON_ACCEPT_SLOTS: &[(&str, &str)] = &[
    // The single serialization bridge: it exists precisely because the guest
    // cannot produce JSON text itself.
    ("agent::json_text", "value"),
];

/// Slots that still publish a dynamic or legacy-null schema.
///
/// This is a quarantine, not an allow-list of correct behaviour: the audit
/// asserts the set **equals** the dynamic slots the catalog actually declares,
/// so it can only shrink. Converting a slot without deleting its entry fails,
/// and declaring a new dynamic slot without listing it fails.
#[allow(dead_code)] // read by the boundary audit
pub const PENDING_DYNAMIC_SLOTS: &[(&str, &str)] = &[
    // Open provider/tool JSON inputs: the adapter validates resources before
    // forwarding them, but the parameter schema is still dynamic.
    ("cap::process_spawn", "limits"),
    // ---- auth: revealed only because the audit now covers every published
    // namespace; the auth/oauth/config trunks are a later round.
    // ---- config: revealed only because the audit now covers every published
    // namespace; the auth/oauth/config trunks are a later round.
    // ---- oauth: revealed only because the audit now covers every published
    // namespace; the auth/oauth/config trunks are a later round.
    ("oauth::transport_capture", "payload"),
    ("oauth::transport_capture_result", "payload"),
    ("oauth::transport_payload", "payload"),
    ("oauth::transport_payload_result", "payload"),
    // ---- state: revealed only because the audit now covers every published
    // namespace; the auth/oauth/config trunks are a later round.
    ("state::read", "return"),
    ("state::write", "return"),
    // ---- stream: revealed only because the audit now covers every published
    // namespace; the auth/oauth/config trunks are a later round.
    ("stream::emit", "value"),
    // ---- timer: revealed only because the audit now covers every published
    // namespace; the auth/oauth/config trunks are a later round.
    ("timer::at", "callback"),
    ("timer::every", "callback"),
    // ---- workspace: revealed only because the audit now covers every published
    // namespace; the auth/oauth/config trunks are a later round.
];

/// Standard runtime builtins the restricted registry may admit.
pub const RESTRICTED_STANDARD_BUILTINS: &[&str] = &[
    "json::encode",
    "json::decode",
    "stream::emit",
    "bytes::to_utf8",
    "bytes::to_utf8_lossy",
    "bytes::to_array_u8",
    "bytes::from_utf8",
    "sqlite::open",
    "sqlite::execute",
    "sqlite::query",
    "sqlite::transaction",
    "sqlite::close",
    "http::request::new",
    "http::request::set_header",
    "http::request::set_body_text",
    "http::request::set_body_bytes",
    "http::client::request",
    "http::client::sse",
    "http::response::status",
    "http::response::url",
    "http::response::header_values",
    "http::response::header_names",
    "http::response::body",
    "http::headers::values",
    "http::headers::names",
    "http::sse_summary::outcome",
    "http::sse_summary::status",
    "http::sse_summary::headers",
    "http::sse_summary::url",
    "http::sse_summary::items",
    "http::sse_summary::bytes_received",
    "http::sse_summary::bytes_sent",
];

pub fn static_stack_descriptor(
    schema: HostFunctionSchema,
    adapter: fn(&mut Vm, &[Value]) -> VmResult<CallOutcome>,
) -> HostFunctionDescriptor {
    HostFunctionDescriptor {
        schema,
        binding: HostBindingDescriptor {
            kind: HostBindingKind::StaticStack,
        },
        effects: Vec::new(),
        adapter: HostAdapterDescriptor::StaticStack(adapter),
        resource_types: Vec::new(),
    }
}

pub fn absorb_catalog(builder: &mut HostApiBuilder, catalog: &HostApiCatalog) {
    for resource in catalog.resources() {
        builder.resource(resource.clone());
    }
    for named in catalog.structs() {
        builder.named_struct(named.clone());
    }
    for function in catalog.functions() {
        builder.function(function.clone());
    }
}

/// The core stream adapter yields Unit; publish that concrete result instead
/// of the descriptor's legacy dynamic return, retaining its original adapter.
pub fn typed_stream_emit_descriptor() -> HostFunctionDescriptor {
    let mut descriptor = standard_host_modules()
        .iter()
        .find(|module| module.name == "context")
        .expect("standard context module")
        .owned_descriptors()
        .into_iter()
        .find(|descriptor| descriptor.schema.name == "stream::emit")
        .expect("standard stream adapter");
    descriptor.schema.return_type = HostTypeSchema::Unit;
    descriptor
}

pub fn compose_with_standard(modules: &[HostModuleDescriptor]) -> Arc<HostApiCatalog> {
    let mut builder = HostApiBuilder::new();
    absorb_catalog(&mut builder, standard_host_catalog().as_ref());
    // `stream::emit` is descriptor-only in frozen core (not on the guest
    // catalog). Its adapter yields Unit; publish the concrete result so
    // compile fingerprints match the runtime registry.
    builder.function(typed_stream_emit_descriptor().schema);
    for module in modules {
        absorb_catalog(
            &mut builder,
            &module
                .catalog()
                .unwrap_or_else(|error| panic!("host module '{}' catalog: {error}", module.name)),
        );
    }
    Arc::new(
        builder
            .build()
            .unwrap_or_else(|error| panic!("composed host catalog: {error}")),
    )
}

#[allow(dead_code)]
pub fn schema_is_unknown(schema: &HostTypeSchema) -> bool {
    matches!(schema, HostTypeSchema::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::agent_host::{agent_host_catalog, agent_host_module};
    use rustscript_vm::HostFunctionRegistry;
    use std::collections::BTreeSet;

    /// One declared host slot, addressed exactly as the audit lists it.
    struct Slot {
        function: String,
        slot: String,
        schema: HostTypeSchema,
    }

    /// Every published slot is audited: the whole composed catalog, not only
    /// the agent/capability namespaces. A slot added by config/auth/oauth is
    /// held to the same rules.
    fn slot_table(catalog: &HostApiCatalog) -> Vec<Slot> {
        let mut table = Vec::new();
        for function in catalog.functions() {
            for param in &function.params {
                table.push(Slot {
                    function: function.name.clone(),
                    slot: param.name.clone(),
                    schema: param.ty.clone(),
                });
            }
            table.push(Slot {
                function: function.name.clone(),
                slot: "return".to_string(),
                schema: function.return_type.clone(),
            });
        }
        table
    }

    /// Path lookup used by the open-slot lists, which may address one field of a
    /// declared named struct. Resolved from the same table the quarantine uses,
    /// so a mutated table moves every direction of the audit together.
    fn table_schema<'a>(
        slots: &'a [Slot],
        function: &str,
        slot: &str,
    ) -> Option<&'a HostTypeSchema> {
        if let Some(field_name) = slot.strip_prefix("return.") {
            let entry = slots
                .iter()
                .find(|entry| entry.function == function && entry.slot == "return")?;
            let HostTypeSchema::Named { fields, .. } = &entry.schema else {
                return None;
            };
            return fields
                .iter()
                .find(|field| field.name == field_name)
                .map(|field| &field.ty);
        }
        slots
            .iter()
            .find(|entry| entry.function == function && entry.slot == slot)
            .map(|entry| &entry.schema)
    }

    /// A dynamic or legacy-null slot anywhere in the declared schema.
    fn dynamic(schema: &HostTypeSchema) -> bool {
        match schema {
            HostTypeSchema::Unknown | HostTypeSchema::Null | HostTypeSchema::Optional(_) => true,
            HostTypeSchema::Array(inner)
            | HostTypeSchema::Map(inner)
            | HostTypeSchema::Option(inner) => dynamic(inner),
            HostTypeSchema::Result { ok, err } => dynamic(ok) || dynamic(err),
            HostTypeSchema::Callable { params, result } => {
                params.iter().any(dynamic) || dynamic(result)
            }
            HostTypeSchema::Named { fields, .. } => fields.iter().any(|field| dynamic(&field.ty)),
            HostTypeSchema::Unit
            | HostTypeSchema::Int
            | HostTypeSchema::Float
            | HostTypeSchema::Number
            | HostTypeSchema::Bool
            | HostTypeSchema::String
            | HostTypeSchema::Bytes
            | HostTypeSchema::Resource(_) => false,
        }
    }

    /// A slot that is exactly one serialized-text field (not a struct that
    /// happens to contain text somewhere).
    fn exactly_text(schema: &HostTypeSchema) -> bool {
        matches!(schema, HostTypeSchema::String)
    }

    /// A slot that accepts arbitrary native JSON.
    fn exactly_open(schema: &HostTypeSchema) -> bool {
        matches!(schema, HostTypeSchema::Unknown)
    }

    fn entries(list: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        list.iter()
            .map(|(function, slot)| (function.to_string(), slot.to_string()))
            .collect()
    }

    /// Bidirectional audit. The three lists are the contract:
    ///
    /// * no declared **return** slot is dynamic — the guest compiler rejects
    ///   those outright, so publishing one is a host bug;
    /// * every dynamic parameter slot is either quarantined or an explicit
    ///   open-input slot, and every entry in either list is still dynamic (so
    ///   the quarantine can only shrink);
    /// * every open-text entry resolves to a slot that is itself `String`;
    /// * every open-input entry resolves to a slot that is itself `Unknown` and
    ///   is a parameter;
    /// * the lists never overlap.
    fn audit(slots: &[Slot]) -> Vec<String> {
        let mut problems = Vec::new();
        let pending = entries(PENDING_DYNAMIC_SLOTS);
        let text = entries(OPEN_JSON_TEXT_SLOTS);
        let accept = entries(OPEN_JSON_ACCEPT_SLOTS);

        let dynamic_returns: BTreeSet<(String, String)> = slots
            .iter()
            .filter(|slot| slot.slot == "return" && dynamic(&slot.schema))
            .map(|slot| (slot.function.clone(), slot.slot.clone()))
            .collect();
        // A dynamic return is legal only while it is still quarantined; it can
        // never be an accepted open input, because the guest cannot receive one.
        for (function, slot) in dynamic_returns.difference(&pending) {
            problems.push(format!(
                "dynamic return slot is not quarantined: {function} {slot}"
            ));
        }

        let dynamic_slots: BTreeSet<(String, String)> = slots
            .iter()
            .filter(|slot| dynamic(&slot.schema))
            .map(|slot| (slot.function.clone(), slot.slot.clone()))
            .collect();

        for (function, slot) in dynamic_slots.difference(&pending) {
            if accept.contains(&(function.clone(), slot.clone())) {
                continue;
            }
            problems.push(format!(
                "dynamic slot is not quarantined in PENDING_DYNAMIC_SLOTS: {function} {slot}"
            ));
        }
        for (function, slot) in pending.difference(&dynamic_slots) {
            problems.push(format!(
                "PENDING_DYNAMIC_SLOTS entry is no longer dynamic: {function} {slot}"
            ));
        }
        for (function, slot) in accept.difference(&dynamic_slots) {
            problems.push(format!(
                "OPEN_JSON_ACCEPT_SLOTS entry is not an open schema: {function} {slot}"
            ));
        }
        for (function, slot) in &text {
            if pending.contains(&(function.clone(), slot.clone()))
                || accept.contains(&(function.clone(), slot.clone()))
            {
                problems.push(format!(
                    "slot is listed as both open text and open/quarantined: {function} {slot}"
                ));
            }
        }
        for (function, slot) in &accept {
            if slot == "return" {
                problems.push(format!(
                    "OPEN_JSON_ACCEPT_SLOTS must name a parameter, not a return: {function}"
                ));
            }
            match table_schema(slots, function, slot) {
                None => problems.push(format!(
                    "OPEN_JSON_ACCEPT_SLOTS entry has no matching declared slot: {function} {slot}"
                )),
                Some(entry) if !exactly_open(entry) => problems.push(format!(
                    "open-input slot is not exactly Unknown: {function} {slot}"
                )),
                Some(_) => {}
            }
        }
        for (function, slot) in &text {
            match table_schema(slots, function, slot) {
                None => problems.push(format!(
                    "OPEN_JSON_TEXT_SLOTS entry has no matching declared slot: {function} {slot}"
                )),
                Some(entry) if dynamic(entry) => problems.push(format!(
                    "open-text slot is dynamic again: {function} {slot}"
                )),
                Some(entry) if !exactly_text(entry) => problems.push(format!(
                    "open-text slot is not itself a String: {function} {slot}"
                )),
                Some(_) => {}
            }
        }
        problems
    }

    #[test]
    fn host_slot_audit_is_bidirectional_for_the_published_catalog() {
        let slots = slot_table(agent_host_catalog().as_ref());
        let problems = audit(&slots);
        assert!(problems.is_empty(), "host slot audit failed: {problems:#?}");
        assert!(
            !PENDING_DYNAMIC_SLOTS.is_empty(),
            "the quarantine must keep naming the slots that still have to move"
        );
    }

    #[test]
    fn host_slot_audit_covers_every_published_namespace() {
        let catalog = agent_host_catalog();
        let slots = slot_table(catalog.as_ref());
        let audited: BTreeSet<&str> = slots
            .iter()
            .map(|slot| slot.function.split_once("::").map_or("", |(root, _)| root))
            .collect();
        for root in ["config", "oauth", "auth", "cap", "agent", "agent_runtime"] {
            assert!(
                audited.contains(root),
                "the audit must cover the '{root}' namespace"
            );
        }
    }

    #[test]
    fn host_slot_audit_catches_every_direction_of_drift() {
        let mut slots = slot_table(agent_host_catalog().as_ref());

        // A converted slot regressing to a dynamic schema is caught.
        let converted = slots
            .iter_mut()
            .find(|slot| slot.function == "agent::parse_json_object" && slot.slot == "return")
            .expect("converted slot is declared");
        converted.schema = HostTypeSchema::Unknown;
        let problems = audit(&slots);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("OPEN_JSON_TEXT_SLOTS entry")
                    || problem.contains("open-text slot is dynamic again")),
            "a regressed open-text slot must fail the audit: {problems:#?}"
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("not quarantined in PENDING_DYNAMIC_SLOTS")),
            "an unlisted dynamic slot must fail the audit: {problems:#?}"
        );

        // A dynamic return slot is a hard failure, not a quarantine entry.
        let mut slots = slot_table(agent_host_catalog().as_ref());
        let returned = slots
            .iter_mut()
            .find(|slot| slot.function == "cap::fs_metadata" && slot.slot == "return")
            .expect("declared return");
        returned.schema = HostTypeSchema::Unknown;
        let problems = audit(&slots);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("dynamic return slot is not quarantined")),
            "an unquarantined dynamic return must fail: {problems:#?}"
        );

        // A converted slot whose quarantine entry was kept is caught too.
        let mut slots = slot_table(agent_host_catalog().as_ref());
        // The mutation targets a slot that is *still* quarantined; a converted
        // slot (for example `agent::approval_storage payload`, which is text
        // now) can no longer stand in for the stale-entry direction.
        let pending = slots
            .iter_mut()
            .find(|slot| slot.function == "cap::process_spawn" && slot.slot == "limits")
            .expect("quarantined slot is declared");
        pending.schema = HostTypeSchema::String;
        let problems = audit(&slots);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("no longer dynamic")),
            "a stale quarantine entry must fail the audit: {problems:#?}"
        );

        // An open-text entry that resolves to a struct with some text field is
        // not enough: the slot itself has to be the text.
        let mut slots = slot_table(agent_host_catalog().as_ref());
        let nested = slots
            .iter_mut()
            .find(|slot| slot.function == "agent::parse_json_object" && slot.slot == "return")
            .expect("converted slot is declared");
        nested.schema = HostTypeSchema::Named {
            name: "EnvelopeWithText".to_string(),
            fields: vec![rustscript_vm::HostStructField::new(
                "value",
                HostTypeSchema::Named {
                    name: "NestedText".to_string(),
                    fields: vec![rustscript_vm::HostStructField::new(
                        "text",
                        HostTypeSchema::String,
                    )],
                },
            )],
        };
        let problems = audit(&slots);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("not itself a String")),
            "only the exact field may be listed: {problems:#?}"
        );
    }

    #[test]
    fn open_text_slots_are_concrete_and_disjoint_from_the_quarantine() {
        for (function, slot) in OPEN_JSON_TEXT_SLOTS {
            assert!(
                !PENDING_DYNAMIC_SLOTS
                    .iter()
                    .any(|(name, allowed)| name == function && allowed == slot),
                "{function} {slot} must not be quarantined and converted at once"
            );
        }
        assert!(
            !PENDING_DYNAMIC_SLOTS
                .iter()
                .any(|(name, _)| *name == "agent::parse_json_object"),
            "a converted function must not stay quarantined"
        );
        let slots = slot_table(agent_host_catalog().as_ref());
        for (function, slot) in OPEN_JSON_TEXT_SLOTS {
            let entry = table_schema(&slots, function, slot)
                .unwrap_or_else(|| panic!("{function} {slot} is declared"));
            assert!(!dynamic(entry), "{function} {slot} must be concrete");
            assert!(exactly_text(entry), "{function} {slot} is the text itself");
        }
        for (function, slot) in OPEN_JSON_ACCEPT_SLOTS {
            let entry = table_schema(&slots, function, slot)
                .unwrap_or_else(|| panic!("{function} {slot} is declared"));
            assert!(exactly_open(entry), "{function} {slot} is open");
        }
    }

    #[test]
    fn duplicate_agent_module_install_fails() {
        let catalog = agent_host_catalog();
        let mut registry = HostFunctionRegistry::restricted();
        agent_host_module()
            .install_from_catalog(&mut registry, catalog.as_ref())
            .expect("first install");
        let error = agent_host_module()
            .install_from_catalog(&mut registry, catalog.as_ref())
            .expect_err("duplicate install must fail");
        let message = error.to_string();
        assert!(
            message.contains("already")
                || message.contains("duplicate")
                || message.contains("conflict")
                || message.contains("registered"),
            "unexpected duplicate error: {message}"
        );
    }

    #[test]
    fn restricted_registry_rejects_unlisted_function() {
        let catalog = agent_host_catalog();
        let mut registry = HostFunctionRegistry::restricted();
        agent_host_module()
            .install_from_catalog(&mut registry, catalog.as_ref())
            .expect("install agent");
        let error = registry
            .allow_builtin("agent::definitely_not_registered")
            .expect_err("unlisted builtin must stay denied");
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn composed_catalog_includes_standard_http_and_sqlite() {
        let catalog = agent_host_catalog();
        let names: Vec<_> = catalog
            .functions()
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert!(names.contains(&"http::client::request"));
        assert!(names.contains(&"sqlite::open"));
        assert!(names.contains(&"agent::provider_call"));
    }

    #[test]
    fn restricted_http_allowlist_excludes_ambient_core_builtins() {
        let http: Vec<_> = RESTRICTED_STANDARD_BUILTINS
            .iter()
            .copied()
            .filter(|name| name.starts_with("http::"))
            .collect();
        assert_eq!(
            http,
            [
                "http::request::new",
                "http::request::set_header",
                "http::request::set_body_text",
                "http::request::set_body_bytes",
                "http::client::request",
                "http::client::sse",
                "http::response::status",
                "http::response::url",
                "http::response::header_values",
                "http::response::header_names",
                "http::response::body",
                "http::headers::values",
                "http::headers::names",
                "http::sse_summary::outcome",
                "http::sse_summary::status",
                "http::sse_summary::headers",
                "http::sse_summary::url",
                "http::sse_summary::items",
                "http::sse_summary::bytes_received",
                "http::sse_summary::bytes_sent",
            ]
        );
        for denied in ["io::open", "io::popen", "runtime::exit", "runtime::sleep"] {
            assert!(!RESTRICTED_STANDARD_BUILTINS.contains(&denied));
        }
    }
}
