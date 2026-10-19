//! Captured, bounded RSS declarations sealed into Native call authority.
//! No wire value, descriptor risk, or public tool name can construct authority.
use std::collections::BTreeMap;
use std::sync::Arc;

use super::{ManagedCodeIdentity, ManagedExternalEffects};
use crate::capabilities::CapabilityRisk;
use crate::registry::{ToolRegistry, ToolRegistrySnapshot};
use crate::tool_schema::ToolDescriptor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedPolicyClass {
    WorkspaceRead,
    WorkspaceWrite,
    ForegroundProcess,
    ProcessControl,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum ManagedNativeOperation {
    FsRead,
    FsWrite,
    ProcessSpawn,
    OwnedProcessUse,
}
impl ManagedNativeOperation {
    pub(crate) fn required_risk(self) -> CapabilityRisk {
        match self {
            Self::FsRead => CapabilityRisk::Read,
            Self::FsWrite => CapabilityRisk::Write,
            Self::ProcessSpawn | Self::OwnedProcessUse => CapabilityRisk::Execute,
        }
    }
}
impl ManagedPolicyClass {
    fn parse(tag: &str) -> Result<Self, String> {
        match tag {
            "workspace_read" => Ok(Self::WorkspaceRead),
            "workspace_write" => Ok(Self::WorkspaceWrite),
            "foreground_process" => Ok(Self::ForegroundProcess),
            "process_control" => Ok(Self::ProcessControl),
            _ => Err("managed unknown operation declaration".into()),
        }
    }
    pub(crate) fn expected_risk(self) -> CapabilityRisk {
        match self {
            Self::WorkspaceRead => CapabilityRisk::Read,
            Self::WorkspaceWrite => CapabilityRisk::Write,
            Self::ForegroundProcess | Self::ProcessControl => CapabilityRisk::Execute,
        }
    }
    pub(crate) fn required_effect(self) -> Result<(&'static str, &'static str), String> {
        match self {
            Self::WorkspaceRead => Ok(("workspace.fs.read", "bound_workspace")),
            Self::WorkspaceWrite => Ok(("workspace.fs.write", "bound_workspace")),
            Self::ForegroundProcess => Ok(("process.spawn", "bound_process")),
            Self::ProcessControl => Err("managed_open_effect_unsupported".into()),
        }
    }
    pub(crate) fn writable(self) -> bool {
        matches!(self, Self::WorkspaceWrite | Self::ForegroundProcess)
    }
    pub(crate) fn external_effects(self) -> ManagedExternalEffects {
        match self {
            Self::ForegroundProcess => ManagedExternalEffects::OutsideTreeNotReverted,
            _ => ManagedExternalEffects::NoneClaimed,
        }
    }
    fn allows_operation(self, operation: ManagedNativeOperation) -> bool {
        matches!(
            (self, operation),
            (
                Self::WorkspaceRead | Self::WorkspaceWrite | Self::ForegroundProcess,
                ManagedNativeOperation::FsRead
            ) | (Self::WorkspaceWrite, ManagedNativeOperation::FsWrite)
                | (
                    Self::ForegroundProcess,
                    ManagedNativeOperation::ProcessSpawn | ManagedNativeOperation::OwnedProcessUse
                )
        )
    }
}

#[derive(Debug)]
pub(crate) struct ManagedToolPolicyCatalog {
    package_id: String,
    artifact_id: String,
    export: String,
    declarations: BTreeMap<String, ManagedPolicyClass>,
    descriptors: ToolRegistrySnapshot,
}

/// Bound the borrowed VM carrier without first constructing a JSON tree.
fn vm_json_bounds(value: &rustscript_vm::Value, limit: usize) -> Result<(), String> {
    fn walk(
        value: &rustscript_vm::Value,
        depth: usize,
        nodes: &mut usize,
        bytes: &mut usize,
        limit: usize,
    ) -> Result<(), String> {
        use rustscript_vm::Value;
        if depth > 128 || *nodes >= 4096 {
            return Err("managed metadata complexity".into());
        }
        *nodes += 1;
        let mut charge = |n: usize| -> Result<(), String> {
            *bytes = bytes.checked_add(n).ok_or("managed metadata overflow")?;
            if *bytes > limit {
                return Err("managed metadata bytes".into());
            }
            Ok(())
        };
        match value {
            Value::Null => charge(4),
            Value::Bool(_) => charge(5),
            Value::Int(_) => charge(20),
            Value::Float(n) if n.is_finite() => charge(32),
            Value::String(text) => {
                if text.len() > 65536 {
                    return Err("managed metadata string".into());
                }
                let quoted = 2 + text
                    .chars()
                    .map(|c| match c {
                        '\"' | '\\' | '\n' | '\r' | '\t' | '\u{0008}' | '\u{000c}' => 2,
                        '\u{0000}'..='\u{001f}' => 6,
                        _ => c.len_utf8(),
                    })
                    .sum::<usize>();
                charge(quoted)
            }
            Value::Array(values) => {
                if values.len() > 4096 {
                    return Err("managed metadata array".into());
                }
                charge(2 + values.len())?;
                for item in values.iter() {
                    walk(item, depth + 1, nodes, bytes, limit)?;
                }
                Ok(())
            }
            Value::Map(fields) => {
                if fields.len() > 4096 {
                    return Err("managed metadata map".into());
                }
                charge(2 + fields.len() * 2)?;
                for (key, item) in fields.iter() {
                    if !matches!(key, Value::String(_)) {
                        return Err("managed metadata key".into());
                    }
                    walk(key, depth + 1, nodes, bytes, limit)?;
                    walk(item, depth + 1, nodes, bytes, limit)?;
                }
                Ok(())
            }
            _ => Err("managed metadata must be pure JSON data".into()),
        }
    }
    walk(value, 0, &mut 0, &mut 0, limit)
}
fn vm_fields(value: &rustscript_vm::Value, names: &[&str]) -> Result<(), String> {
    let rustscript_vm::Value::Map(fields) = value else {
        return Err("managed catalog map required".into());
    };
    if fields.len()!=names.len() || fields.iter().any(|(key,_)| !matches!(key,rustscript_vm::Value::String(text) if names.contains(&text.as_str()))) {return Err("managed catalog fields".into());}
    Ok(())
}
fn vm_field<'a>(
    value: &'a rustscript_vm::Value,
    name: &str,
) -> Result<&'a rustscript_vm::Value, String> {
    let rustscript_vm::Value::Map(fields) = value else {
        return Err("managed catalog map required".into());
    };
    fields
        .iter()
        .find_map(|(key, value)| match key {
            rustscript_vm::Value::String(text) if text.as_str() == name => Some(value),
            _ => None,
        })
        .ok_or_else(|| "managed catalog field required".into())
}
fn vm_string(value: &rustscript_vm::Value, limit: usize) -> Result<&str, String> {
    match value {
        rustscript_vm::Value::String(text) if text.len() <= limit => Ok(text.as_str()),
        _ => Err("managed catalog string bound/type".into()),
    }
}
fn preflight_catalog(value: &rustscript_vm::Value) -> Result<(), String> {
    use rustscript_vm::Value;
    vm_fields(value, &["declarations", "descriptors"])?;
    let (Value::Array(declarations), Value::Array(descriptors)) = (
        vm_field(value, "declarations")?,
        vm_field(value, "descriptors")?,
    ) else {
        return Err("managed catalog arrays required".into());
    };
    if declarations.is_empty() || declarations.len() > 64 || descriptors.len() > 64 {
        return Err("managed catalog entry bound".into());
    }
    for declaration in declarations.iter() {
        vm_fields(declaration, &["tool_name", "operation"])?;
        vm_string(vm_field(declaration, "tool_name")?, 64)?;
        ManagedPolicyClass::parse(vm_string(vm_field(declaration, "operation")?, 64)?)?;
    }
    for descriptor in descriptors.iter() {
        vm_fields(
            descriptor,
            &["name", "description", "toolset", "risk_class", "schema"],
        )?;
        vm_string(vm_field(descriptor, "name")?, 64)?;
        vm_string(vm_field(descriptor, "description")?, 4096)?;
        vm_string(vm_field(descriptor, "toolset")?, 64)?;
        vm_string(vm_field(descriptor, "risk_class")?, 64)?;
    }
    vm_json_bounds(value, super::journal::METADATA_BYTES)?;
    for descriptor in descriptors.iter() {
        vm_json_bounds(vm_field(descriptor, "schema")?, 65536)?;
    }
    Ok(())
}

/// Copy only a fully preflighted, bounded VM JSON carrier.
fn bounded_json(value: &rustscript_vm::Value) -> Result<serde_json::Value, String> {
    fn visit(
        value: &rustscript_vm::Value,
        depth: usize,
        nodes: &mut usize,
        bytes: &mut usize,
    ) -> Result<serde_json::Value, String> {
        use rustscript_vm::Value;
        if depth > 128 || *nodes >= 4096 {
            return Err("managed metadata complexity".into());
        }
        *nodes += 1;
        let mut charge = |n: usize| -> Result<(), String> {
            *bytes = bytes.checked_add(n).ok_or("managed metadata overflow")?;
            if *bytes > super::journal::METADATA_BYTES {
                return Err("managed metadata bytes".into());
            }
            Ok(())
        };
        match value {
            Value::Null => {
                charge(4)?;
                Ok(serde_json::Value::Null)
            }
            Value::Bool(b) => {
                charge(5)?;
                Ok((*b).into())
            }
            Value::Int(n) => {
                charge(20)?;
                Ok((*n).into())
            }
            Value::Float(n) => {
                charge(32)?;
                serde_json::Number::from_f64(*n)
                    .map(serde_json::Value::Number)
                    .ok_or("managed nonfinite number".into())
            }
            Value::String(s) => {
                if s.len() > 65536 {
                    return Err("managed metadata string".into());
                }
                charge(
                    serde_json::to_string(s.as_ref())
                        .map_err(|_| "managed string")?
                        .len(),
                )?;
                Ok(serde_json::Value::String(s.to_string()))
            }
            Value::Array(a) => {
                if a.len() > 4096 {
                    return Err("managed metadata array".into());
                }
                charge(2 + a.len())?;
                let mut out = Vec::with_capacity(a.len());
                for v in a.iter() {
                    out.push(visit(v, depth + 1, nodes, bytes)?);
                }
                Ok(out.into())
            }
            Value::Map(m) => {
                if m.len() > 4096 {
                    return Err("managed metadata map".into());
                }
                charge(2 + m.len() * 2)?;
                let mut out = serde_json::Map::new();
                for (key, v) in m.iter() {
                    let serde_json::Value::String(key) = visit(key, depth + 1, nodes, bytes)?
                    else {
                        return Err("managed metadata key".into());
                    };
                    if out
                        .insert(key, visit(v, depth + 1, nodes, bytes)?)
                        .is_some()
                    {
                        return Err("managed duplicate key".into());
                    }
                }
                Ok(out.into())
            }
            _ => Err("managed metadata must be pure JSON data".into()),
        }
    }
    visit(value, 0, &mut 0, &mut 0)
}
impl ManagedToolPolicyCatalog {
    // Only the verified capture path consumes this parser. Synthetic parser
    // fixtures do not authenticate a builtin or mint a run binding.
    pub(crate) fn from_captured_value(
        package_id: &str,
        artifact_id: &str,
        export: &str,
        value: &rustscript_vm::Value,
    ) -> Result<Arc<Self>, String> {
        preflight_catalog(value)?;
        let value = bounded_json(value)?;
        let fields = value.as_object().ok_or("managed catalog map required")?;
        if fields.len() != 2 {
            return Err("managed catalog fields".into());
        }
        let decls = fields
            .get("declarations")
            .and_then(serde_json::Value::as_array)
            .ok_or("managed declarations required")?;
        let descs = fields
            .get("descriptors")
            .and_then(serde_json::Value::as_array)
            .ok_or("managed descriptors required")?;
        if decls.is_empty() || decls.len() > 64 || descs.len() > 64 {
            return Err("managed catalog entry bound".into());
        }
        let mut declarations = BTreeMap::new();
        for declaration in decls {
            let row = declaration
                .as_object()
                .ok_or("managed declaration map required")?;
            if row.len() != 2 {
                return Err("managed declaration fields".into());
            }
            let name = row
                .get("tool_name")
                .and_then(serde_json::Value::as_str)
                .ok_or("managed declaration name")?;
            if name.len() > 64 {
                return Err("managed declaration name bound".into());
            }
            let tag = row
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .ok_or("managed declaration operation")?;
            if declarations
                .insert(name.into(), ManagedPolicyClass::parse(tag)?)
                .is_some()
            {
                return Err("managed duplicate declaration".into());
            }
        }
        let mut descriptors = Vec::with_capacity(descs.len());
        for value in descs {
            let row = value.as_object().ok_or("managed descriptor map")?;
            if row.len() != 5
                || !["name", "description", "toolset", "risk_class", "schema"]
                    .iter()
                    .all(|key| row.contains_key(*key))
            {
                return Err("managed descriptor fields".into());
            }
            if row["description"].as_str().is_none_or(|s| s.len() > 4096)
                || serde_json::to_vec(&row["schema"])
                    .map_err(|_| "managed schema")?
                    .len()
                    > 65536
            {
                return Err("managed descriptor bound".into());
            }
            descriptors.push(
                serde_json::from_value::<ToolDescriptor>(value.clone())
                    .map_err(|_| "managed descriptor types")?,
            );
        }
        let descriptors = ToolRegistry::from_descriptors(descriptors)
            .map_err(|_| "managed descriptor registry")?
            .snapshot();
        if declarations.len() != descriptors.len() {
            return Err("managed catalog coverage".into());
        }
        for descriptor in descriptors.descriptors() {
            let class = declarations
                .get(&descriptor.name)
                .ok_or("managed catalog coverage")?;
            if class.expected_risk().as_str() != descriptor.risk_class {
                return Err("managed captured risk mismatch".into());
            }
        }
        Ok(Arc::new(Self {
            package_id: package_id.into(),
            artifact_id: artifact_id.into(),
            export: export.into(),
            declarations,
            descriptors,
        }))
    }
    pub(crate) fn matches_code(&self, code: &ManagedCodeIdentity) -> bool {
        self.package_id == code.package_id
            && self.artifact_id == code.artifact_id
            && self.export == code.export
    }
    pub(crate) fn seal(
        self: &Arc<Self>,
        code: &ManagedCodeIdentity,
        snapshot: &ToolRegistrySnapshot,
        name: &str,
        risk: CapabilityRisk,
        arguments: &str,
    ) -> Result<Arc<SealedManagedCallPolicy>, String> {
        if !self.matches_code(code) || code.registry_identity != snapshot.identity() {
            return Err("managed catalog binding mismatch".into());
        }
        let class = *self
            .declarations
            .get(name)
            .ok_or("managed tool has no captured declaration")?;
        let descriptor = self
            .descriptors
            .descriptor(name)
            .ok_or("managed captured descriptor missing")?;
        if snapshot.descriptor(name) != Some(descriptor) || class.expected_risk() != risk {
            return Err("managed admitted descriptor/risk mismatch".into());
        }
        class.required_effect()?;
        let args: serde_json::Value =
            serde_json::from_str(arguments).map_err(|_| "managed canonical arguments")?;
        if class == ManagedPolicyClass::ForegroundProcess
            && args.get("background").and_then(serde_json::Value::as_bool) == Some(true)
        {
            return Err("managed_open_effect_unsupported".into());
        }
        Ok(Arc::new(SealedManagedCallPolicy {
            catalog: Arc::clone(self),
            code: code.clone(),
            tool_name: name.into(),
            class,
        }))
    }
}

#[derive(Debug)]
pub(crate) struct SealedManagedCallPolicy {
    catalog: Arc<ManagedToolPolicyCatalog>,
    code: ManagedCodeIdentity,
    tool_name: String,
    class: ManagedPolicyClass,
}
impl SealedManagedCallPolicy {
    pub(crate) fn expected_risk(&self) -> CapabilityRisk {
        self.class.expected_risk()
    }
    pub(crate) fn class(&self) -> ManagedPolicyClass {
        self.class
    }
    pub(crate) fn matches(
        &self,
        catalog: &Arc<ManagedToolPolicyCatalog>,
        code: &ManagedCodeIdentity,
        name: &str,
    ) -> bool {
        Arc::ptr_eq(&self.catalog, catalog)
            && self.catalog.matches_code(code)
            && &self.code == code
            && self.tool_name == name
    }
    pub(crate) fn allows_operation(&self, operation: ManagedNativeOperation) -> bool {
        self.class.allows_operation(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn synthetic() -> Value {
        // Parser/class coverage only: this renamed fixture is not an
        // authenticated embedding package or end-to-end builtin execution.
        json!({"declarations":[{"tool_name":"renamed_reader","operation":"workspace_read"}],"descriptors":[{"name":"renamed_reader","description":"synthetic parser fixture","toolset":"coding","risk_class":"read","schema":{"type":"object"}}]})
    }
    fn parse(v: &Value) -> Result<Arc<ManagedToolPolicyCatalog>, String> {
        ManagedToolPolicyCatalog::from_captured_value(
            "synthetic-package",
            "synthetic-artifact",
            "invoke",
            &crate::domain::json_to_vm_value(v),
        )
    }
    #[test]
    fn vm_catalog_bounds_precede_copying_oversized_rows() {
        let mut value = synthetic();
        let mut descriptor = value["descriptors"][0].clone();
        descriptor["description"] = json!("x".repeat(60000));
        value["descriptors"] = json!(vec![descriptor; 65]);
        assert_eq!(parse(&value).unwrap_err(), "managed catalog entry bound");
    }

    #[test]
    fn synthetic_parser_is_closed_bounded_and_has_no_risk_or_name_defaults() {
        let value = synthetic();
        assert!(parse(&value).is_ok());
        let mut variants = Vec::new();
        let mut wrong = value.clone();
        wrong.as_object_mut().unwrap().remove("declarations");
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["declarations"][0]["extra"] = json!(true);
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["declarations"][0]["operation"] = json!("unknown");
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["declarations"][0]["tool_name"] = json!("missing");
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["declarations"] = json!([value["declarations"][0], value["declarations"][0]]);
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["descriptors"][0]["risk_class"] = json!("write");
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["descriptors"][0]["extra"] = json!({});
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["descriptors"][0]["description"] = json!("x".repeat(4097));
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["declarations"][0]["tool_name"] = json!("x".repeat(65));
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["descriptors"][0]["schema"] = json!({"description":"x".repeat(65537)});
        variants.push(wrong);
        let mut wrong = value.clone();
        wrong["declarations"] = json!(vec![value["declarations"][0].clone(); 65]);
        variants.push(wrong);
        let mut metadata = value.clone();
        metadata["descriptors"]=json!((0..20).map(|i| json!({"name":format!("bounded_{i}"),"description":"metadata bound","toolset":"coding","risk_class":"read","schema":{"type":"object","description":"x".repeat(60000)}})).collect::<Vec<_>>());
        metadata["declarations"] = json!(
            (0..20)
                .map(|i| json!({"tool_name":format!("bounded_{i}"),"operation":"workspace_read"}))
                .collect::<Vec<_>>()
        );
        assert!(parse(&metadata).unwrap_err().contains("metadata bytes"));
        for wrong in variants {
            assert!(parse(&wrong).is_err());
        }
        let mut depth = json!(true);
        for _ in 0..129 {
            depth = json!([depth]);
        }
        let mut wrong = value.clone();
        wrong["descriptors"][0]["schema"] = depth;
        assert!(parse(&wrong).is_err());
        let mut wrong = value.clone();
        wrong["descriptors"][0]["schema"] = json!({"enum":vec![0;4097]});
        assert!(parse(&wrong).is_err());
    }
    #[test]
    fn synthetic_catalog_identity_and_admitted_snapshot_are_exact_extras_grant_nothing() {
        let catalog = parse(&synthetic()).unwrap();
        let snapshot = catalog.descriptors.clone();
        let mut code = ManagedCodeIdentity {
            graph_id: "graph-a".into(),
            activation_generation: 1,
            graph_ref_id: "ref-a".into(),
            package_id: "synthetic-package".into(),
            artifact_id: "synthetic-artifact".into(),
            export: "invoke".into(),
            registry_identity: snapshot.identity().into(),
            effect_contract_version: 1,
        };
        let policy = catalog
            .seal(
                &code,
                &snapshot,
                "renamed_reader",
                CapabilityRisk::Read,
                "{}",
            )
            .unwrap();
        assert!(policy.allows_operation(ManagedNativeOperation::FsRead));
        assert!(!policy.allows_operation(ManagedNativeOperation::FsWrite));
        assert!(!policy.allows_operation(ManagedNativeOperation::ProcessSpawn));
        assert!(
            catalog
                .seal(
                    &code,
                    &snapshot,
                    "renamed_reader",
                    CapabilityRisk::Write,
                    "{}"
                )
                .is_err()
        );
        let mut wrong = code.clone();
        wrong.artifact_id = "other".into();
        assert!(!catalog.matches_code(&wrong));
        let mut wrong = code.clone();
        wrong.package_id = "other".into();
        assert!(!catalog.matches_code(&wrong));
        let mut wrong = code.clone();
        wrong.export = "other".into();
        assert!(!catalog.matches_code(&wrong));
        let mut wrong = code.clone();
        wrong.activation_generation += 1;
        assert!(!policy.matches(&catalog, &wrong, "renamed_reader"));
        let mut wrong = code.clone();
        wrong.graph_ref_id = "other".into();
        assert!(!policy.matches(&catalog, &wrong, "renamed_reader"));
        let mut extra = snapshot.descriptors()[0].clone();
        extra.name = "extra_reader".into();
        let extended = ToolRegistry::from_descriptors([snapshot.descriptors()[0].clone(), extra])
            .unwrap()
            .snapshot();
        assert!(
            catalog
                .seal(
                    &code,
                    &extended,
                    "renamed_reader",
                    CapabilityRisk::Read,
                    "{}"
                )
                .is_err()
        );
        code.registry_identity = extended.identity().into();
        assert!(
            catalog
                .seal(
                    &code,
                    &extended,
                    "renamed_reader",
                    CapabilityRisk::Read,
                    "{}"
                )
                .is_ok()
        );
        assert!(
            catalog
                .seal(&code, &extended, "extra_reader", CapabilityRisk::Read, "{}")
                .is_err()
        );
        assert!(policy.matches(
            &catalog,
            &ManagedCodeIdentity {
                registry_identity: snapshot.identity().into(),
                ..code
            },
            "renamed_reader"
        ));
        assert!(
            !ManagedPolicyClass::ForegroundProcess
                .allows_operation(ManagedNativeOperation::FsWrite)
        );
        assert!(
            ManagedPolicyClass::ForegroundProcess
                .allows_operation(ManagedNativeOperation::OwnedProcessUse)
        );
        assert!(
            ManagedPolicyClass::ProcessControl
                .required_effect()
                .is_err()
        );
    }
}
