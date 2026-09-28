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

/// Genuinely open JSON/tool payloads that remain `HostTypeSchema::Unknown`.
/// Each entry is (`function_name`, `slot`) where slot is a parameter label
/// or `return.<field>` for a named-struct field.
#[allow(dead_code)]
pub const DYNAMIC_HOST_SLOTS: &[(&str, &str)] = &[
    ("agent::provider_call", "request"),
    ("agent::provider_call", "return"),
    ("agent_runtime::tool_prepare", "metadata"),
    ("agent_runtime::tool_commit", "result"),
    ("cap::artifact_put", "metadata"),
    ("cap::artifact_put_result", "metadata"),
    ("cap::artifact_put", "return"),
    ("cap::artifact_put_result", "return"),
    ("cap::artifact_get", "return"),
    ("cap::artifact_reference", "return"),
    ("agent::parse_json_object", "return"),
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
    "http::sse_summary::url",
    "http::sse_summary::header_values",
    "http::sse_summary::header_names",
    "http::sse_summary::items",
    "http::sse_summary::bytes_received",
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

pub fn compose_with_standard(modules: &[HostModuleDescriptor]) -> Arc<HostApiCatalog> {
    let mut builder = HostApiBuilder::new();
    absorb_catalog(&mut builder, standard_host_catalog().as_ref());
    // `stream::emit` is descriptor-only in frozen core (not on the guest
    // catalog). Agent RSS still imports it, so publish the owned schema so
    // compile fingerprints match the runtime registry. json/bytes stay
    // namespaced builtins via allow_builtin.
    for module in standard_host_modules() {
        if module.name != "context" {
            continue;
        }
        for descriptor in module.owned_descriptors() {
            builder.function(descriptor.schema.clone());
        }
    }
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

    fn slot_allowed(function: &str, slot: &str) -> bool {
        DYNAMIC_HOST_SLOTS
            .iter()
            .any(|(name, allowed)| *name == function && *allowed == slot)
    }

    #[test]
    fn dynamic_slots_are_explicit_and_complete_for_agent_module() {
        let catalog = agent_host_catalog();
        let mut unexpected = Vec::new();
        for function in catalog.functions() {
            if !function.name.starts_with("agent::")
                && !function.name.starts_with("agent_runtime::")
                && !function.name.starts_with("cap::")
            {
                continue;
            }
            for param in &function.params {
                if schema_is_unknown(&param.ty) && !slot_allowed(&function.name, &param.name) {
                    unexpected.push(format!("{} param {}", function.name, param.name));
                }
            }
            match &function.return_type {
                HostTypeSchema::Named { fields, .. } => {
                    for field in fields {
                        let slot = format!("return.{}", field.name);
                        if schema_is_unknown(&field.ty) && !slot_allowed(&function.name, &slot) {
                            unexpected.push(format!("{} {slot}", function.name));
                        }
                    }
                }
                other if schema_is_unknown(other) && !slot_allowed(&function.name, "return") => {
                    unexpected.push(format!("{} return", function.name));
                }
                _ => {}
            }
        }
        assert!(
            unexpected.is_empty(),
            "unlisted Unknown host slots: {unexpected:?}"
        );
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
                "http::sse_summary::url",
                "http::sse_summary::header_values",
                "http::sse_summary::header_names",
                "http::sse_summary::items",
                "http::sse_summary::bytes_received",
            ]
        );
        for denied in ["io::open", "io::popen", "runtime::exit", "runtime::sleep"] {
            assert!(!RESTRICTED_STANDARD_BUILTINS.contains(&denied));
        }
    }
}
