use std::{collections::BTreeSet, io};

use serde_json::{Map, Value, json};

use crate::config::MAX_PROCESS_TOOL_TIMEOUT;

use super::types::{NativeToolExecutor, RiskClass, ToolDescriptor, Toolset};

/// Computes a SHA-256 digest for the deterministic registry fingerprint.
///
/// This digest is a resume-consistency value, not a signature and not an
/// authentication or authorization mechanism.
fn sha256_hex(bytes: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let bit_length = (bytes.len() as u64).wrapping_mul(8);
    let mut state = INITIAL;
    let mut chunks = bytes.chunks_exact(64);
    for chunk in &mut chunks {
        let block: &[u8; 64] = chunk
            .try_into()
            .expect("chunks_exact yields 64-byte blocks");
        sha256_compress(&mut state, block);
    }

    let remainder = chunks.remainder();
    let mut final_blocks = [0_u8; 128];
    final_blocks[..remainder.len()].copy_from_slice(remainder);
    final_blocks[remainder.len()] = 0x80;
    let final_len = if remainder.len() < 56 { 64 } else { 128 };
    final_blocks[final_len - 8..final_len].copy_from_slice(&bit_length.to_be_bytes());
    for block in final_blocks[..final_len].chunks_exact(64) {
        let block: &[u8; 64] = block
            .try_into()
            .expect("chunks_exact yields 64-byte blocks");
        sha256_compress(&mut state, block);
    }

    let mut digest = String::with_capacity(64);
    for word in state {
        use std::fmt::Write as _;
        write!(digest, "{word:08x}").expect("writing to a String cannot fail");
    }
    digest
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const ROUND_CONSTANTS: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let mut schedule = [0_u32; 64];
    for (index, word) in schedule.iter_mut().take(16).enumerate() {
        let start = index * 4;
        *word = u32::from_be_bytes([
            block[start],
            block[start + 1],
            block[start + 2],
            block[start + 3],
        ]);
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ ((!e) & g);
        let temporary1 = h
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temporary2 = s0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temporary1);
        d = c;
        c = b;
        b = a;
        a = temporary1.wrapping_add(temporary2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub const MAX_REGISTRY_ENTRIES: usize = 64;
pub const MAX_TOOL_NAME_BYTES: usize = 64;
pub const MAX_DESCRIPTION_BYTES: usize = 4096;
pub const MAX_SCHEMA_BYTES: usize = 65_536;
pub const MAX_SCHEMA_NODES: usize = 4096;
pub const MAX_SCHEMA_DEPTH: usize = 128;
const MAX_DIAGNOSTIC_BYTES: usize = 512;
const MAX_ERROR_FIELD_BYTES: usize = 128;
const MAX_POINTER_BYTES: usize = 256;
const MAX_RISK_CLASS_BYTES: usize = 7;
const MAX_TOOLSET_BYTES: usize = 7;

const BUILTIN_TOOL_ORDER: [&str; 6] = [
    "read_file",
    "search_files",
    "write_file",
    "patch",
    "terminal",
    "process",
];

/// An inert native slot paired with one public tool descriptor.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolRegistryEntry {
    pub descriptor: ToolDescriptor,
    pub executor: NativeToolExecutor,
}

impl ToolRegistryEntry {
    pub fn new(descriptor: ToolDescriptor, executor: NativeToolExecutor) -> Self {
        Self {
            descriptor,
            executor,
        }
    }

    pub fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    pub fn executor(&self) -> &NativeToolExecutor {
        &self.executor
    }
}

/// Typed construction failures for a native tool registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolRegistryError {
    TooManyEntries {
        limit: usize,
    },
    EmptyName,
    InvalidToolName {
        name: String,
    },
    ToolNameTooLong {
        name: String,
        limit: usize,
    },
    EmptyDescription {
        name: String,
    },
    DescriptionTooLong {
        name: String,
        limit: usize,
    },
    EmptyRiskClass {
        name: String,
    },
    UnsupportedRiskClass {
        name: String,
        risk_class: String,
    },
    UnsupportedToolset {
        name: String,
        toolset: String,
    },
    ExecutorNameMismatch {
        name: String,
        executor_name: String,
    },
    ExecutorToolsetMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    ExecutorRiskClassMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    DuplicateName {
        name: String,
    },
    SchemaTooLarge {
        name: String,
        limit: usize,
        actual: usize,
    },
    SchemaTooComplex {
        name: String,
        limit: usize,
        actual: usize,
    },
    SchemaTooDeep {
        name: String,
        limit: usize,
        actual: usize,
    },
    UnsupportedSchemaDialect {
        name: String,
    },
    InvalidSchema {
        name: String,
        reason: String,
    },
}

impl std::fmt::Display for ToolRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyEntries { limit } => {
                write!(formatter, "tool registry exceeds the {limit}-entry limit")
            }
            Self::EmptyName => formatter.write_str("tool descriptor name must not be empty"),
            Self::InvalidToolName { name } => {
                write!(formatter, "tool name {name:?} is not provider-safe ASCII")
            }
            Self::ToolNameTooLong { limit, .. } => {
                write!(formatter, "tool name exceeds the {limit}-byte limit")
            }
            Self::EmptyDescription { name } => {
                write!(
                    formatter,
                    "tool descriptor {name:?} must have a description"
                )
            }
            Self::DescriptionTooLong { name, limit } => {
                write!(
                    formatter,
                    "tool descriptor {name:?} exceeds the {limit}-byte description limit"
                )
            }
            Self::EmptyRiskClass { name } => {
                write!(formatter, "tool descriptor {name:?} must have a risk class")
            }
            Self::UnsupportedRiskClass { name, .. } => {
                write!(formatter, "tool {name:?} uses an unsupported risk class")
            }
            Self::UnsupportedToolset { name, toolset } => {
                write!(
                    formatter,
                    "tool {name:?} uses unsupported toolset {toolset:?}"
                )
            }
            Self::ExecutorNameMismatch {
                name,
                executor_name,
            } => write!(
                formatter,
                "tool {name:?} is paired with executor slot {executor_name:?}"
            ),
            Self::ExecutorToolsetMismatch {
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "tool {name:?} has toolset {actual:?}; executor requires {expected:?}"
            ),
            Self::ExecutorRiskClassMismatch {
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "tool {name:?} has risk class {actual:?}; executor requires {expected:?}"
            ),
            Self::DuplicateName { name } => write!(formatter, "duplicate tool name {name:?}"),
            Self::SchemaTooLarge { name, limit, .. } => {
                write!(
                    formatter,
                    "tool {name:?} schema exceeds the {limit}-byte limit"
                )
            }
            Self::SchemaTooComplex { name, limit, .. } => {
                write!(
                    formatter,
                    "tool {name:?} schema exceeds the {limit}-node limit"
                )
            }
            Self::SchemaTooDeep { name, limit, .. } => {
                write!(
                    formatter,
                    "tool {name:?} schema exceeds the depth-{limit} limit"
                )
            }
            Self::UnsupportedSchemaDialect { name } => {
                write!(
                    formatter,
                    "tool {name:?} declares an unsupported JSON Schema dialect"
                )
            }
            Self::InvalidSchema { name, reason } => {
                write!(
                    formatter,
                    "tool {name:?} has an invalid JSON schema: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for ToolRegistryError {}

/// The category of a bounded schema diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaValidationErrorKind {
    InvalidRoot,
    InvalidKeyword,
    UnsupportedSchemaDialect,
    SchemaTooLarge,
    SchemaTooComplex,
    SchemaTooDeep,
    MetaSchema,
}

/// A structural JSON Schema validation failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaValidationError {
    pub path: String,
    pub keyword: String,
    pub kind: SchemaValidationErrorKind,
    pub message: String,
}

impl std::fmt::Display for SchemaValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SchemaValidationError {}

impl SchemaValidationError {
    fn new(path: &str, keyword: &str, kind: SchemaValidationErrorKind) -> Self {
        let path = bounded_pointer(path);
        let keyword = bounded_token(keyword, MAX_ERROR_FIELD_BYTES);
        let message = format!("keyword={keyword} kind={kind:?} path={path}");
        Self {
            path,
            keyword,
            kind,
            message: bounded_message(&message, MAX_DIAGNOSTIC_BYTES),
        }
    }

    fn new_with_message(
        path: String,
        keyword: String,
        kind: SchemaValidationErrorKind,
        message: String,
    ) -> Self {
        Self {
            path,
            keyword,
            kind,
            message: bounded_message(&message, MAX_DIAGNOSTIC_BYTES),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SchemaPreflightError {
    InvalidRoot,
    UnsupportedSchemaDialect { path: String },
    SchemaTooLarge { actual: usize },
    SchemaTooComplex { actual: usize },
    SchemaTooDeep { actual: usize },
}

fn schema_preflight_error(error: SchemaPreflightError) -> SchemaValidationError {
    match error {
        SchemaPreflightError::InvalidRoot => {
            SchemaValidationError::new("/", "schema", SchemaValidationErrorKind::InvalidRoot)
        }
        SchemaPreflightError::UnsupportedSchemaDialect { path } => SchemaValidationError::new(
            &path,
            "$schema",
            SchemaValidationErrorKind::UnsupportedSchemaDialect,
        ),
        SchemaPreflightError::SchemaTooLarge { actual } => {
            let _ = actual;
            SchemaValidationError::new("/", "schema", SchemaValidationErrorKind::SchemaTooLarge)
        }
        SchemaPreflightError::SchemaTooComplex { actual } => {
            let _ = actual;
            SchemaValidationError::new("/", "schema", SchemaValidationErrorKind::SchemaTooComplex)
        }
        SchemaPreflightError::SchemaTooDeep { actual } => {
            let _ = actual;
            SchemaValidationError::new("/", "schema", SchemaValidationErrorKind::SchemaTooDeep)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SupportedSchemaDialect {
    Draft4,
    Draft6,
    Draft7,
    Draft201909,
    Draft202012,
}

const MAX_SCHEMA_DIALECT_BYTES: usize = "https://json-schema.org/draft/2020-12/schema#".len();

fn supported_schema_draft(uri: &str) -> Option<jsonschema::Draft> {
    let base = uri.strip_suffix('#').unwrap_or(uri);
    if uri.len() > MAX_SCHEMA_DIALECT_BYTES {
        return None;
    }

    let dialect = match base {
        "http://json-schema.org/draft-04/schema" => SupportedSchemaDialect::Draft4,
        "http://json-schema.org/draft-06/schema" => SupportedSchemaDialect::Draft6,
        "http://json-schema.org/draft-07/schema" => SupportedSchemaDialect::Draft7,
        "https://json-schema.org/draft/2019-09/schema" => SupportedSchemaDialect::Draft201909,
        "https://json-schema.org/draft/2020-12/schema" => SupportedSchemaDialect::Draft202012,
        _ => return None,
    };

    Some(match dialect {
        SupportedSchemaDialect::Draft4 => jsonschema::Draft::Draft4,
        SupportedSchemaDialect::Draft6 => jsonschema::Draft::Draft6,
        SupportedSchemaDialect::Draft7 => jsonschema::Draft::Draft7,
        SupportedSchemaDialect::Draft201909 => jsonschema::Draft::Draft201909,
        SupportedSchemaDialect::Draft202012 => jsonschema::Draft::Draft202012,
    })
}

fn inspect_schema_limits(schema: &Value) -> Result<(), SchemaPreflightError> {
    if !schema.is_boolean() && !schema.is_object() {
        return Err(SchemaPreflightError::InvalidRoot);
    }

    let mut metrics = SchemaMetrics::default();
    let mut pending = vec![(schema, 0_usize, String::new())];
    while let Some((value, depth, path)) = pending.pop() {
        if let Value::String(string) = value
            && let Some(actual) = schema_string_serialized_lower_bound(string)
        {
            return Err(SchemaPreflightError::SchemaTooLarge { actual });
        }
        if let Value::Object(object) = value {
            for key in object.keys() {
                if let Some(actual) = schema_string_serialized_lower_bound(key) {
                    return Err(SchemaPreflightError::SchemaTooLarge { actual });
                }
            }
        }

        if depth > MAX_SCHEMA_DEPTH {
            return Err(SchemaPreflightError::SchemaTooDeep { actual: depth });
        }

        metrics.nodes = metrics.nodes.saturating_add(1);
        if metrics.nodes > MAX_SCHEMA_NODES {
            return Err(SchemaPreflightError::SchemaTooComplex {
                actual: metrics.nodes,
            });
        }

        match value {
            Value::Object(object) => {
                if let Some(Value::String(uri)) = object.get("$schema")
                    && supported_schema_draft(uri).is_none()
                {
                    return Err(SchemaPreflightError::UnsupportedSchemaDialect {
                        path: child_pointer(&path, "$schema"),
                    });
                }

                if depth == MAX_SCHEMA_DEPTH && !object.is_empty() {
                    return Err(SchemaPreflightError::SchemaTooDeep { actual: depth + 1 });
                }
                let frontier = metrics
                    .nodes
                    .saturating_add(pending.len())
                    .saturating_add(object.len());
                if frontier > MAX_SCHEMA_NODES {
                    return Err(SchemaPreflightError::SchemaTooComplex { actual: frontier });
                }
                for (key, child) in object.iter().rev() {
                    let mut child_path = path.clone();
                    push_pointer_segment(&mut child_path, key);
                    pending.push((child, depth + 1, child_path));
                }
            }
            Value::Array(values) => {
                if depth == MAX_SCHEMA_DEPTH && !values.is_empty() {
                    return Err(SchemaPreflightError::SchemaTooDeep { actual: depth + 1 });
                }
                let frontier = metrics
                    .nodes
                    .saturating_add(pending.len())
                    .saturating_add(values.len());
                if frontier > MAX_SCHEMA_NODES {
                    return Err(SchemaPreflightError::SchemaTooComplex { actual: frontier });
                }
                for (index, child) in values.iter().enumerate().rev() {
                    let mut child_path = path.clone();
                    push_pointer_segment(&mut child_path, &index.to_string());
                    pending.push((child, depth + 1, child_path));
                }
            }
            _ => {}
        }
    }

    let mut writer = SizeLimitWriter {
        size: 0,
        limit: MAX_SCHEMA_BYTES,
        overflowed: false,
    };
    if serde_json::to_writer(&mut writer, schema).is_err() {
        if writer.overflowed {
            return Err(SchemaPreflightError::SchemaTooLarge {
                actual: MAX_SCHEMA_BYTES + 1,
            });
        }
        return Err(SchemaPreflightError::InvalidRoot);
    }

    Ok(())
}

#[derive(Default)]
struct SchemaMetrics {
    nodes: usize,
}

fn child_pointer(path: &str, segment: &str) -> String {
    let mut child = path.to_string();
    push_pointer_segment(&mut child, segment);
    child
}

fn push_pointer_segment(path: &mut String, segment: &str) {
    if path.len() >= MAX_POINTER_BYTES {
        if path.len() > MAX_POINTER_BYTES {
            let mut end = MAX_POINTER_BYTES;
            while !path.is_char_boundary(end) {
                end -= 1;
            }
            path.truncate(end);
        }
        return;
    }
    path.push('/');
    for character in segment.chars() {
        let encoded = match character {
            '~' => "~0",
            '/' => "~1",
            character if character.is_ascii_graphic() => {
                if path.len() == MAX_POINTER_BYTES {
                    break;
                }
                path.push(character);
                continue;
            }
            _ => "?",
        };
        if encoded.len() > MAX_POINTER_BYTES - path.len() {
            break;
        }
        path.push_str(encoded);
    }
}

/// Returns the O(1) serialized-size lower bound for one JSON string.
///
/// Escaping can only increase the encoded size. The two quote bytes are
/// included so a component that already cannot fit the schema budget is
/// rejected during iterative preflight, before whole-schema serialization.
fn schema_string_serialized_lower_bound(value: &str) -> Option<usize> {
    let actual = value.len().saturating_add(2);
    (actual > MAX_SCHEMA_BYTES).then_some(actual)
}

fn bounded_pointer(pointer: &str) -> String {
    let mut bounded = String::new();
    for character in pointer.chars() {
        let replacement = if character.is_ascii_graphic() || character == '/' {
            character
        } else {
            '?'
        };
        if bounded.len() + replacement.len_utf8() > MAX_POINTER_BYTES {
            break;
        }
        bounded.push(replacement);
    }
    if bounded.is_empty() {
        bounded.push('/');
    }
    bounded
}

fn bounded_token(value: &str, limit: usize) -> String {
    let mut bounded = String::new();
    for character in value.chars() {
        let replacement = if character.is_ascii_graphic() {
            character
        } else {
            '?'
        };
        if bounded.len() + replacement.len_utf8() > limit {
            break;
        }
        bounded.push(replacement);
    }
    bounded
}

fn bounded_message(value: &str, limit: usize) -> String {
    let mut bounded = String::new();
    for character in value.chars() {
        let replacement = if character.is_ascii() && !character.is_ascii_control() {
            character
        } else {
            '?'
        };
        if bounded.len() + replacement.len_utf8() > limit {
            break;
        }
        bounded.push(replacement);
    }
    bounded
}

struct SizeLimitWriter {
    size: usize,
    limit: usize,
    overflowed: bool,
}

impl io::Write for SizeLimitWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.size) {
            self.size = self.limit.saturating_add(1);
            self.overflowed = true;
            return Err(io::Error::other("serialized schema exceeds its budget"));
        }
        self.size += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validation_kind_name(kind: &jsonschema::error::ValidationErrorKind) -> &'static str {
    use jsonschema::error::ValidationErrorKind;

    match kind {
        ValidationErrorKind::AdditionalItems { .. } => "AdditionalItems",
        ValidationErrorKind::AdditionalProperties { .. } => "AdditionalProperties",
        ValidationErrorKind::AnyOf { .. } => "AnyOf",
        ValidationErrorKind::BacktrackLimitExceeded { .. } => "BacktrackLimitExceeded",
        ValidationErrorKind::RegexEngineFailure { .. } => "RegexEngineFailure",
        ValidationErrorKind::Constant { .. } => "Constant",
        ValidationErrorKind::Contains => "Contains",
        ValidationErrorKind::ContentEncoding { .. } => "ContentEncoding",
        ValidationErrorKind::ContentMediaType { .. } => "ContentMediaType",
        ValidationErrorKind::Custom { .. } => "Custom",
        ValidationErrorKind::Enum { .. } => "Enum",
        ValidationErrorKind::ExclusiveMaximum { .. } => "ExclusiveMaximum",
        ValidationErrorKind::ExclusiveMinimum { .. } => "ExclusiveMinimum",
        ValidationErrorKind::FalseSchema => "FalseSchema",
        ValidationErrorKind::Format { .. } => "Format",
        ValidationErrorKind::FromUtf8 { .. } => "FromUtf8",
        ValidationErrorKind::MaxItems { .. } => "MaxItems",
        ValidationErrorKind::Maximum { .. } => "Maximum",
        ValidationErrorKind::MaxLength { .. } => "MaxLength",
        ValidationErrorKind::MaxProperties { .. } => "MaxProperties",
        ValidationErrorKind::MinItems { .. } => "MinItems",
        ValidationErrorKind::Minimum { .. } => "Minimum",
        ValidationErrorKind::MinLength { .. } => "MinLength",
        ValidationErrorKind::MinProperties { .. } => "MinProperties",
        ValidationErrorKind::MultipleOf { .. } => "MultipleOf",
        ValidationErrorKind::Not { .. } => "Not",
        ValidationErrorKind::OneOfMultipleValid { .. } => "OneOfMultipleValid",
        ValidationErrorKind::OneOfNotValid { .. } => "OneOfNotValid",
        ValidationErrorKind::Pattern { .. } => "Pattern",
        ValidationErrorKind::PropertyNames { .. } => "PropertyNames",
        ValidationErrorKind::Required { .. } => "Required",
        ValidationErrorKind::Type { .. } => "Type",
        ValidationErrorKind::UnevaluatedItems { .. } => "UnevaluatedItems",
        ValidationErrorKind::UnevaluatedProperties { .. } => "UnevaluatedProperties",
        ValidationErrorKind::UniqueItems => "UniqueItems",
        ValidationErrorKind::Referencing(_) => "Referencing",
    }
}

/// Validates a JSON Schema document before it can enter the registry.
///
/// Boolean schemas are valid. Object schemas are checked against maintained
/// JSON Schema meta-schema validators, which validate standard keyword shapes
/// recursively while retaining unknown extension keywords. Untagged schemas
/// use both the current Draft 2020-12 vocabulary and the Draft 7 meta-schema:
/// the latter preserves the existing tuple-form `items` and `additionalItems`
/// compatibility, while the former covers newer keywords such as
/// `contentSchema`.
pub fn validate_json_schema(schema: &Value) -> Result<(), SchemaValidationError> {
    inspect_schema_limits(schema).map_err(schema_preflight_error)?;

    if schema.is_boolean() {
        return Ok(());
    }

    let draft = schema
        .as_object()
        .and_then(|object| object.get("$schema"))
        .and_then(Value::as_str)
        .and_then(supported_schema_draft);

    match draft {
        Some(jsonschema::Draft::Draft4) => {
            jsonschema::draft4::meta::validate(schema).map_err(schema_validation_error)
        }
        Some(jsonschema::Draft::Draft6) => {
            jsonschema::draft6::meta::validate(schema).map_err(schema_validation_error)
        }
        Some(jsonschema::Draft::Draft7) => {
            jsonschema::draft7::meta::validate(schema).map_err(schema_validation_error)
        }
        Some(jsonschema::Draft::Draft201909) => {
            jsonschema::draft201909::meta::validate(schema).map_err(schema_validation_error)
        }
        Some(jsonschema::Draft::Draft202012) => {
            jsonschema::draft202012::meta::validate(schema).map_err(schema_validation_error)
        }
        Some(jsonschema::Draft::Unknown) => Err(SchemaValidationError::new(
            "/$schema",
            "$schema",
            SchemaValidationErrorKind::UnsupportedSchemaDialect,
        )),
        Some(_) => Err(SchemaValidationError::new(
            "/$schema",
            "$schema",
            SchemaValidationErrorKind::UnsupportedSchemaDialect,
        )),
        None => validate_modern_schema_with_legacy_compatibility(schema),
    }
}

fn validate_modern_schema_with_legacy_compatibility(
    schema: &Value,
) -> Result<(), SchemaValidationError> {
    if let Some(items) = root_legacy_tuple_items(schema) {
        validate_legacy_tuple_items(items)?;
    }

    // Draft 7 is the only bundled meta-schema that validates tuple-form
    // `items` and `additionalItems`. Its validation is retained for those
    // legacy keywords; Draft 2020-12 below validates the newer vocabulary.
    jsonschema::draft7::meta::validate(schema).map_err(schema_validation_error)?;

    let validator = jsonschema::draft202012::meta::validator();
    for error in validator.iter_errors(schema) {
        let instance_path = error.instance_path().to_string();
        if is_root_legacy_tuple_items_error(schema, &instance_path, error.kind()) {
            continue;
        }
        return Err(schema_validation_error(error));
    }
    Ok(())
}

fn root_legacy_tuple_items(schema: &Value) -> Option<&[Value]> {
    schema
        .as_object()
        .and_then(|object| object.get("items"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn validate_legacy_tuple_items(items: &[Value]) -> Result<(), SchemaValidationError> {
    if items.is_empty() {
        return Err(SchemaValidationError::new(
            "/items",
            "items",
            SchemaValidationErrorKind::MetaSchema,
        ));
    }

    for (index, item) in items.iter().enumerate() {
        if let Err(error) = jsonschema::draft7::meta::validate(item) {
            return Err(prefix_legacy_tuple_error(
                index,
                schema_validation_error(error),
            ));
        }
    }
    Ok(())
}

fn prefix_legacy_tuple_error(index: usize, error: SchemaValidationError) -> SchemaValidationError {
    let suffix = error.path.strip_prefix('/').unwrap_or(&error.path);
    let raw_path = if suffix.is_empty() {
        format!("/items/{index}")
    } else {
        format!("/items/{index}/{suffix}")
    };
    let path = bounded_pointer(&raw_path);
    let message = format!(
        "keyword={} kind={:?} path={path}",
        error.keyword, error.kind
    );
    SchemaValidationError::new_with_message(
        path,
        error.keyword,
        SchemaValidationErrorKind::MetaSchema,
        message,
    )
}

fn is_root_legacy_tuple_items_error(
    schema: &Value,
    instance_path: &str,
    kind: &jsonschema::error::ValidationErrorKind,
) -> bool {
    instance_path == "/items"
        && matches!(kind, jsonschema::error::ValidationErrorKind::Type { .. })
        && root_legacy_tuple_items(schema).is_some()
}

fn schema_validation_error(error: jsonschema::ValidationError<'_>) -> SchemaValidationError {
    let raw_path = error.instance_path().to_string();
    let path = bounded_pointer(&raw_path);
    let fallback_keyword = error.kind().keyword();
    let keyword = schema_keyword_from_pointer(&raw_path, fallback_keyword);
    let kind = validation_kind_name(error.kind());
    let message = format!("keyword={keyword} kind={kind} path={path}");
    SchemaValidationError::new_with_message(
        path,
        keyword,
        SchemaValidationErrorKind::MetaSchema,
        message,
    )
}

fn schema_keyword_from_pointer(pointer: &str, fallback: &str) -> String {
    let candidate = pointer
        .rsplit('/')
        .next()
        .filter(|candidate| !candidate.is_empty())
        .map(|candidate| candidate.replace("~1", "/").replace("~0", "~"));
    bounded_token(
        candidate.as_deref().unwrap_or(fallback),
        MAX_ERROR_FIELD_BYTES,
    )
}

/// An immutable, deterministic registry view suitable for attaching to a run.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolRegistrySnapshot {
    entries: Box<[ToolRegistryEntry]>,
    descriptors: Box<[ToolDescriptor]>,
    names: Box<[String]>,
    identity: String,
}

impl ToolRegistrySnapshot {
    pub fn entries(&self) -> &[ToolRegistryEntry] {
        &self.entries
    }

    pub fn descriptors(&self) -> &[ToolDescriptor] {
        &self.descriptors
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Stable, deterministic identity of the ordered descriptor/executor set.
    ///
    /// This is a resume-consistency fingerprint. It does not authenticate a
    /// caller, grant permission, or replace service/native authorization.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn descriptor(&self, name: &str) -> Option<&ToolDescriptor> {
        self.entries
            .iter()
            .find(|entry| entry.descriptor.name == name)
            .map(ToolRegistryEntry::descriptor)
    }

    /// Returns the provider-facing descriptor array without exposing registry
    /// entry internals.
    pub fn schemas(&self) -> Value {
        Value::Array(
            self.descriptors
                .iter()
                .map(|descriptor| {
                    serde_json::to_value(descriptor)
                        .expect("ToolDescriptor contains only serializable fields")
                })
                .collect(),
        )
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Validated native tool registry.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolRegistry {
    snapshot: ToolRegistrySnapshot,
}

impl ToolRegistry {
    /// Constructs a registry from entries.
    ///
    /// The first pass only performs bounded structural and policy checks. It
    /// stops at the entry cap and rejects over-sized descriptors before any
    /// meta-schema compilation or identity hashing. The second pass performs
    /// the comparatively expensive schema validation, after which the ordered
    /// snapshot and its resume fingerprint are frozen.
    pub fn new<I>(entries: I) -> Result<Self, ToolRegistryError>
    where
        I: IntoIterator<Item = ToolRegistryEntry>,
    {
        let mut collected = Vec::with_capacity(MAX_REGISTRY_ENTRIES);
        let mut names = BTreeSet::new();

        for entry in entries {
            if collected.len() == MAX_REGISTRY_ENTRIES {
                return Err(ToolRegistryError::TooManyEntries {
                    limit: MAX_REGISTRY_ENTRIES,
                });
            }
            preflight_descriptor(&entry, &mut names)?;
            collected.push(entry);
        }

        for entry in &collected {
            validate_json_schema(&entry.descriptor.schema).map_err(|error| {
                ToolRegistryError::InvalidSchema {
                    name: entry.descriptor.name.clone(),
                    reason: error.to_string(),
                }
            })?;
        }

        collected.sort_by(|left, right| {
            compare_tool_names(&left.descriptor.name, &right.descriptor.name)
        });
        let descriptors: Vec<_> = collected
            .iter()
            .map(|entry| entry.descriptor.clone())
            .collect();
        let names: Vec<_> = descriptors
            .iter()
            .map(|descriptor| descriptor.name.clone())
            .collect();
        let identity = registry_identity(&collected);

        Ok(Self {
            snapshot: ToolRegistrySnapshot {
                entries: collected.into_boxed_slice(),
                descriptors: descriptors.into_boxed_slice(),
                names: names.into_boxed_slice(),
                identity,
            },
        })
    }

    pub fn from_entries<I>(entries: I) -> Result<Self, ToolRegistryError>
    where
        I: IntoIterator<Item = ToolRegistryEntry>,
    {
        Self::new(entries)
    }

    /// Builds the initial coding/process registry from inert native slots.
    pub fn builtin() -> Result<Self, ToolRegistryError> {
        Self::new(builtin_entries())
    }

    pub fn default_registry() -> Result<Self, ToolRegistryError> {
        Self::builtin()
    }

    pub fn snapshot(&self) -> ToolRegistrySnapshot {
        self.snapshot.clone()
    }

    pub fn descriptors(&self) -> &[ToolDescriptor] {
        self.snapshot.descriptors()
    }

    pub fn entries(&self) -> &[ToolRegistryEntry] {
        self.snapshot.entries()
    }

    pub fn identity(&self) -> &str {
        self.snapshot.identity()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::builtin().expect("built-in tool registry must be valid")
    }
}

pub fn builtin_tool_registry() -> Result<ToolRegistry, ToolRegistryError> {
    ToolRegistry::builtin()
}

pub fn default_tool_registry() -> Result<ToolRegistry, ToolRegistryError> {
    ToolRegistry::builtin()
}

/// Schema for `timeout_ms` using the compile-time millisecond ceiling when it
/// fits in `u64`. Runtime still enforces `ProcessToolConfig.max_timeout`.
fn timeout_ms_schema() -> Value {
    match u64::try_from(MAX_PROCESS_TOOL_TIMEOUT.as_millis()) {
        Ok(maximum) => json!({"type": "integer", "minimum": 1, "maximum": maximum}),
        Err(_) => json!({"type": "integer", "minimum": 1}),
    }
}

/// Returns the six initial inert registrations in their canonical declaration
/// order. The registry constructor freezes that order for the initial names.
pub fn builtin_entries() -> Vec<ToolRegistryEntry> {
    vec![
        ToolRegistryEntry::new(
            ToolDescriptor::new(
                "read_file",
                "Read bounded text from a workspace file",
                Toolset::CODING,
                "read",
                json!({
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "offset": {"type": "integer", "minimum": 1},
                        "limit": {"type": "integer", "minimum": 1}
                    },
                    "required": ["path"],
                    "additionalProperties": false
                }),
            ),
            NativeToolExecutor::ReadFile,
        ),
        ToolRegistryEntry::new(
            ToolDescriptor::new(
                "search_files",
                "Search workspace files with bounded results",
                Toolset::CODING,
                "read",
                json!({
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "path": {"type": "string"},
                        "target": {"type": "string", "enum": ["content", "files"]},
                        "file_glob": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1},
                        "offset": {"type": "integer", "minimum": 0}
                    },
                    "required": ["pattern"],
                    "additionalProperties": false
                }),
            ),
            NativeToolExecutor::SearchFiles,
        ),
        ToolRegistryEntry::new(
            ToolDescriptor::new(
                "write_file",
                "Write complete workspace file contents",
                Toolset::CODING,
                "write",
                json!({
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"}
                    },
                    "required": ["path", "content"],
                    "additionalProperties": false
                }),
            ),
            NativeToolExecutor::WriteFile,
        ),
        ToolRegistryEntry::new(
            ToolDescriptor::new(
                "patch",
                "Apply a bounded workspace text patch",
                Toolset::CODING,
                "write",
                json!({
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "old_string": {"type": "string"},
                        "new_string": {"type": "string"},
                        "replace_all": {"type": "boolean"}
                    },
                    "required": ["path", "old_string", "new_string"],
                    "additionalProperties": false
                }),
            ),
            NativeToolExecutor::Patch,
        ),
        ToolRegistryEntry::new(
            ToolDescriptor::new(
                "terminal",
                "Run one bounded argv process",
                Toolset::PROCESS,
                "execute",
                json!({
                    "type": "object",
                    "properties": {
                        "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "cwd": {"type": "string"},
                        "timeout_ms": {"type": "integer", "minimum": 1},
                        "max_output_bytes": {"type": "integer", "minimum": 1},
                        "stdin": {"type": "string"}
                    },
                    "required": ["argv"],
                    "additionalProperties": false
                }),
            ),
            NativeToolExecutor::Terminal,
        ),
        ToolRegistryEntry::new(
            ToolDescriptor::new(
                "process",
                "Inspect one owned background process",
                Toolset::PROCESS,
                "execute",
                json!({
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["poll", "wait", "log", "write", "close", "kill"]},
                        "process_id": {"type": "string"},
                        "data": {"type": "string"},
                        "timeout_ms": timeout_ms_schema(),
                        "offset": {"type": "integer", "minimum": 0},
                        "limit": {"type": "integer", "minimum": 1}
                    },
                    "required": ["action", "process_id"],
                    "additionalProperties": false
                }),
            ),
            NativeToolExecutor::Process,
        ),
    ]
}

fn preflight_descriptor(
    entry: &ToolRegistryEntry,
    names: &mut BTreeSet<String>,
) -> Result<(), ToolRegistryError> {
    let descriptor = &entry.descriptor;
    if descriptor.name.len() > MAX_TOOL_NAME_BYTES {
        return Err(ToolRegistryError::ToolNameTooLong {
            name: bounded_string(&descriptor.name, MAX_ERROR_FIELD_BYTES),
            limit: MAX_TOOL_NAME_BYTES,
        });
    }
    if descriptor.name.trim().is_empty() {
        return Err(ToolRegistryError::EmptyName);
    }
    if !is_provider_safe_tool_name(&descriptor.name) {
        return Err(ToolRegistryError::InvalidToolName {
            name: bounded_string(&descriptor.name, MAX_ERROR_FIELD_BYTES),
        });
    }
    if !names.insert(descriptor.name.clone()) {
        return Err(ToolRegistryError::DuplicateName {
            name: descriptor.name.clone(),
        });
    }
    if descriptor.description.len() > MAX_DESCRIPTION_BYTES {
        return Err(ToolRegistryError::DescriptionTooLong {
            name: descriptor.name.clone(),
            limit: MAX_DESCRIPTION_BYTES,
        });
    }
    if descriptor.description.trim().is_empty() {
        return Err(ToolRegistryError::EmptyDescription {
            name: descriptor.name.clone(),
        });
    }
    if descriptor.risk_class.len() > MAX_RISK_CLASS_BYTES {
        return Err(ToolRegistryError::UnsupportedRiskClass {
            name: descriptor.name.clone(),
            risk_class: bounded_string(&descriptor.risk_class, MAX_ERROR_FIELD_BYTES),
        });
    }
    if descriptor.risk_class.trim().is_empty() {
        return Err(ToolRegistryError::EmptyRiskClass {
            name: descriptor.name.clone(),
        });
    }
    if RiskClass::try_from(descriptor.risk_class.as_str()).is_err() {
        return Err(ToolRegistryError::UnsupportedRiskClass {
            name: descriptor.name.clone(),
            risk_class: bounded_string(&descriptor.risk_class, MAX_ERROR_FIELD_BYTES),
        });
    }
    if descriptor.toolset.len() > MAX_TOOLSET_BYTES
        || Toolset::try_from(descriptor.toolset.as_str()).is_err()
    {
        return Err(ToolRegistryError::UnsupportedToolset {
            name: descriptor.name.clone(),
            toolset: bounded_string(&descriptor.toolset, MAX_ERROR_FIELD_BYTES),
        });
    }

    let executor_name = entry.executor.tool_name();
    if executor_name != descriptor.name {
        return Err(ToolRegistryError::ExecutorNameMismatch {
            name: descriptor.name.clone(),
            executor_name: bounded_string(executor_name, MAX_ERROR_FIELD_BYTES),
        });
    }

    let contract = entry.executor.contract();
    debug_assert_eq!(contract.tool_name, descriptor.name);
    if let Some(expected) = contract.toolset
        && descriptor.toolset != expected
    {
        return Err(ToolRegistryError::ExecutorToolsetMismatch {
            name: descriptor.name.clone(),
            expected: expected.to_string(),
            actual: descriptor.toolset.clone(),
        });
    }
    if let Some(expected) = contract.risk_class
        && descriptor.risk_class != expected
    {
        return Err(ToolRegistryError::ExecutorRiskClassMismatch {
            name: descriptor.name.clone(),
            expected: expected.to_string(),
            actual: descriptor.risk_class.clone(),
        });
    }

    inspect_schema_limits(&descriptor.schema).map_err(|error| match error {
        SchemaPreflightError::SchemaTooLarge { actual } => ToolRegistryError::SchemaTooLarge {
            name: descriptor.name.clone(),
            limit: MAX_SCHEMA_BYTES,
            actual,
        },
        SchemaPreflightError::SchemaTooComplex { actual } => ToolRegistryError::SchemaTooComplex {
            name: descriptor.name.clone(),
            limit: MAX_SCHEMA_NODES,
            actual,
        },
        SchemaPreflightError::SchemaTooDeep { actual } => ToolRegistryError::SchemaTooDeep {
            name: descriptor.name.clone(),
            limit: MAX_SCHEMA_DEPTH,
            actual,
        },
        SchemaPreflightError::UnsupportedSchemaDialect { .. } => {
            ToolRegistryError::UnsupportedSchemaDialect {
                name: descriptor.name.clone(),
            }
        }
        SchemaPreflightError::InvalidRoot => ToolRegistryError::InvalidSchema {
            name: descriptor.name.clone(),
            reason: SchemaValidationError::new(
                "/",
                "schema",
                SchemaValidationErrorKind::InvalidRoot,
            )
            .to_string(),
        },
    })
}

fn is_provider_safe_tool_name(name: &str) -> bool {
    name.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn bounded_string(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_string();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn compare_tool_names(left: &str, right: &str) -> std::cmp::Ordering {
    let left_rank = BUILTIN_TOOL_ORDER.iter().position(|name| *name == left);
    let right_rank = BUILTIN_TOOL_ORDER.iter().position(|name| *name == right);

    match (left_rank, right_rank) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => left.cmp(right),
    }
}

fn registry_identity(entries: &[ToolRegistryEntry]) -> String {
    let value = Value::Array(
        entries
            .iter()
            .map(|entry| {
                let mut identity_entry = Map::new();
                identity_entry.insert(
                    "descriptor".to_string(),
                    serde_json::to_value(&entry.descriptor)
                        .expect("ToolDescriptor contains only serializable fields"),
                );
                identity_entry.insert(
                    "executor_contract".to_string(),
                    serde_json::to_value(entry.executor.contract())
                        .expect("NativeExecutorContract must serialize"),
                );
                Value::Object(identity_entry)
            })
            .collect(),
    );
    let canonical = canonicalize_json(&value);
    let bytes = serde_json::to_vec(&canonical).expect("canonical descriptor JSON should serialize");
    format!("sha256:{}", sha256_hex(&bytes))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json).collect()),
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize_json(&object[key]));
            }
            Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_POINTER_BYTES, bounded_pointer, push_pointer_segment, sha256_hex};

    #[test]
    fn pointer_segment_builder_caps_exact_plain_boundaries() {
        for (prefix_len, expected_len) in [(254, 256), (255, 256), (256, 256), (257, 256)] {
            let mut path = "p".repeat(prefix_len);
            push_pointer_segment(&mut path, "x");
            assert_eq!(
                path.len(),
                expected_len,
                "plain segment at prefix length {prefix_len}"
            );
            assert!(path.len() <= MAX_POINTER_BYTES);
        }
    }

    #[test]
    fn pointer_segment_builder_caps_ascii_and_non_ascii_escapes() {
        for (prefix_len, segment, expected_len) in [
            (253, "~", 256),
            (254, "~", 255),
            (255, "~", 256),
            (253, "/", 256),
            (254, "/", 255),
            (255, "/", 256),
            (254, "é", 256),
            (255, "é", 256),
        ] {
            let mut path = "p".repeat(prefix_len);
            push_pointer_segment(&mut path, segment);
            assert_eq!(
                path.len(),
                expected_len,
                "segment {segment:?} at prefix length {prefix_len}"
            );
            assert!(path.len() <= MAX_POINTER_BYTES);
        }

        for length in [255, 256, 257] {
            let pointer = bounded_pointer(&"p".repeat(length));
            assert!(
                pointer.len() <= MAX_POINTER_BYTES,
                "bounded pointer length {length}"
            );
        }
    }

    #[test]
    fn sha256_matches_standard_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_matches_padding_boundary_vectors() {
        for (length, expected) in [
            (
                55,
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            ),
            (
                56,
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            ),
            (
                63,
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            ),
            (
                64,
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                119,
                "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
            ),
            (
                120,
                "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c",
            ),
        ] {
            assert_eq!(sha256_hex(&vec![b'a'; length]), expected, "length={length}");
        }
    }
}
