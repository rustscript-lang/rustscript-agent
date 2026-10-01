use rustscript_vm::{
    CallOutcome, HostFunctionDescriptor, HostResourceType, HostTypeSchema, Value, Vm, VmResult,
};
use serde::Deserializer;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value as Json;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;

use super::{Policy, borrow, desc, error, key, named, object, opt, param, result};

const MAX_JSON_BYTES: usize = 65_536;
const MAX_JSON_DEPTH: usize = 64;
const MAX_POINTER_BYTES: usize = 2048;
const MAX_POINTER_TOKENS: usize = 64;

struct ParsedJson {
    document: Json,
    selected_tokens: Vec<String>,
    selected_number_out_of_range: Cell<bool>,
    #[cfg(test)]
    selected_metadata_storage_bytes: usize,
}

#[derive(Clone, Copy)]
struct JsonNumberToken {
    out_of_range: bool,
}

struct JsonParseContext {
    number_tokens: Vec<JsonNumberToken>,
    next_number: Cell<usize>,
    selected_tokens: Vec<String>,
    selected_number_out_of_range: Cell<bool>,
}

impl JsonParseContext {
    fn next_number_token(&self) -> JsonNumberToken {
        let index = self.next_number.get();
        self.next_number.set(index.saturating_add(1));
        self.number_tokens
            .get(index)
            .copied()
            .unwrap_or(JsonNumberToken {
                out_of_range: false,
            })
    }

    #[cfg(test)]
    fn selected_metadata_storage_bytes(&self) -> usize {
        std::mem::size_of_val(&self.selected_number_out_of_range)
            + std::mem::size_of_val(&self.selected_tokens)
            + self.selected_tokens.capacity() * std::mem::size_of::<String>()
            + self
                .selected_tokens
                .iter()
                .map(String::capacity)
                .sum::<usize>()
    }
}

struct JsonSeed<'a> {
    context: &'a JsonParseContext,
    matched_depth: Option<usize>,
}

impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = Json;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonVisitor {
            context: self.context,
            matched_depth: self.matched_depth,
        })
    }
}

struct JsonVisitor<'a> {
    context: &'a JsonParseContext,
    matched_depth: Option<usize>,
}

impl JsonVisitor<'_> {
    fn next_number_token(&self) -> JsonNumberToken {
        let token = self.context.next_number_token();
        if token.out_of_range && self.matched_depth == Some(self.context.selected_tokens.len()) {
            self.context.selected_number_out_of_range.set(true);
        }
        token
    }
}

impl<'de> Visitor<'de> for JsonVisitor<'_> {
    type Value = Json;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Json::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.next_number_token();
        Ok(Json::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.next_number_token();
        Ok(Json::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.next_number_token();
        serde_json::Number::from_f64(value)
            .map(Json::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Json::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Json::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        let mut index = 0usize;
        while let Some(value) = sequence.next_element_seed(JsonSeed {
            context: self.context,
            matched_depth: self.matched_depth.and_then(|depth| {
                let selected_token = self.context.selected_tokens.get(depth)?;
                (canonical_array_index(selected_token) == Some(index)).then_some(depth + 1)
            }),
        })? {
            values.push(value);
            index += 1;
        }
        Ok(Json::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = serde_json::Map::new();
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(<A::Error as de::Error>::custom("duplicate JSON object key"));
            }
            let matched_depth = self.matched_depth.and_then(|depth| {
                let selected_token = self.context.selected_tokens.get(depth)?;
                (selected_token == &key).then_some(depth + 1)
            });
            let value = map.next_value_seed(JsonSeed {
                context: self.context,
                matched_depth,
            })?;
            fields.insert(key, value);
        }
        Ok(Json::Object(fields))
    }
}

fn is_json_number(token: &str) -> bool {
    let bytes = token.as_bytes();
    let mut index = 0;
    if bytes.first() == Some(&b'-') {
        index += 1;
    }
    match bytes.get(index) {
        Some(b'0') => {
            index += 1;
            if bytes.get(index).is_some_and(u8::is_ascii_digit) {
                return false;
            }
        }
        Some(b'1'..=b'9') => {
            index += 1;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
        }
        _ => return false,
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == fraction_start {
            return false;
        }
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let exponent_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == exponent_start {
            return false;
        }
    }
    index == bytes.len()
}

fn json_number_token(token: &str) -> JsonNumberToken {
    let integer = !token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E'));
    let mantissa_end = token.find(['e', 'E']).unwrap_or(token.len());
    let out_of_range = if integer {
        token.parse::<i64>().is_err()
    } else {
        match token.parse::<f64>() {
            Ok(number) => {
                !number.is_finite()
                    || (number == 0.0
                        && token[..mantissa_end]
                            .bytes()
                            .any(|byte| (b'1'..=b'9').contains(&byte)))
            }
            Err(_) => true,
        }
    };
    JsonNumberToken { out_of_range }
}

fn preprocess_json_numbers(text: &str) -> (String, Vec<JsonNumberToken>) {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut normalized = String::with_capacity(text.len());
    let mut copied_through = 0;
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && matches!(bytes[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            {
                index += 1;
            }
            let token = &text[start..index];
            if is_json_number(token) {
                let info = json_number_token(token);
                tokens.push(info);
                if info.out_of_range {
                    normalized.push_str(&text[copied_through..start]);
                    normalized.push_str(
                        if token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                            "0.0"
                        } else {
                            "0"
                        },
                    );
                    copied_through = index;
                }
            }
            continue;
        }
        index += 1;
    }
    if copied_through == 0 {
        (text.to_owned(), tokens)
    } else {
        normalized.push_str(&text[copied_through..]);
        (normalized, tokens)
    }
}

fn parse_json(text: &str, pointer: &str) -> VmResult<ParsedJson> {
    let (normalized, number_tokens) = preprocess_json_numbers(text);
    let context = JsonParseContext {
        number_tokens,
        next_number: Cell::new(0),
        selected_tokens: decode_pointer_tokens(pointer),
        selected_number_out_of_range: Cell::new(false),
    };
    let mut deserializer = serde_json::Deserializer::from_str(&normalized);
    let document = JsonSeed {
        context: &context,
        matched_depth: Some(0),
    }
    .deserialize(&mut deserializer)
    .map_err(|_| error("public_json_invalid"))?;
    deserializer
        .end()
        .map_err(|_| error("public_json_invalid"))?;
    #[cfg(test)]
    let selected_metadata_storage_bytes = context.selected_metadata_storage_bytes();
    Ok(ParsedJson {
        document,
        selected_tokens: context.selected_tokens,
        selected_number_out_of_range: context.selected_number_out_of_range,
        #[cfg(test)]
        selected_metadata_storage_bytes,
    })
}

fn validate_depth(value: &Json, depth: usize) -> VmResult<()> {
    if depth > MAX_JSON_DEPTH {
        return Err(error("public_json_too_deep"));
    }
    match value {
        Json::Array(values) => {
            for value in values {
                validate_depth(value, depth + 1)?;
            }
        }
        Json::Object(fields) => {
            for value in fields.values() {
                validate_depth(value, depth + 1)?;
            }
        }
        Json::Null | Json::Bool(_) | Json::Number(_) | Json::String(_) => {}
    }
    Ok(())
}

fn validate_pointer(pointer: &str) -> VmResult<()> {
    if pointer.len() > MAX_POINTER_BYTES {
        return Err(error("public_json_pointer_invalid"));
    }
    if pointer.is_empty() {
        return Ok(());
    }
    let Some(tokens) = pointer.strip_prefix('/') else {
        return Err(error("public_json_pointer_invalid"));
    };
    let tokens: Vec<&str> = tokens.split('/').collect();
    if tokens.len() > MAX_POINTER_TOKENS {
        return Err(error("public_json_pointer_invalid"));
    }
    for token in tokens {
        let mut chars = token.chars();
        while let Some(character) = chars.next() {
            if character == '~' && !matches!(chars.next(), Some('0' | '1')) {
                return Err(error("public_json_pointer_invalid"));
            }
        }
    }
    Ok(())
}

fn decode_pointer_tokens(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return Vec::new();
    }
    pointer[1..].split('/').map(decode_pointer_token).collect()
}

fn decode_pointer_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

fn canonical_array_index(token: &str) -> Option<usize> {
    if token == "0" {
        return Some(0);
    }
    let bytes = token.as_bytes();
    if !bytes
        .first()
        .is_some_and(|byte| (b'1'..=b'9').contains(byte))
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    token.parse().ok()
}

fn resolve_pointer<'a>(document: &'a Json, tokens: &[String]) -> Option<&'a Json> {
    let mut current = document;
    for token in tokens {
        current = match current {
            Json::Object(fields) => fields.get(token)?,
            Json::Array(values) => values.get(canonical_array_index(token)?)?,
            Json::Null | Json::Bool(_) | Json::Number(_) | Json::String(_) => return None,
        };
    }
    Some(current)
}

fn public_json_field_type() -> HostTypeSchema {
    named(
        "PublicJsonFieldEnvelope",
        vec![
            ("kind", HostTypeSchema::String),
            ("string_value", opt(HostTypeSchema::String)),
            ("int_value", opt(HostTypeSchema::Int)),
            ("float_value", opt(HostTypeSchema::Float)),
            ("bool_value", opt(HostTypeSchema::Bool)),
            ("length", opt(HostTypeSchema::Int)),
        ],
    )
}

pub(super) fn public_json_field_desc() -> HostFunctionDescriptor {
    desc(
        "oauth::public_json_field",
        vec![
            borrow("policy_handle", key(Policy::KEY)),
            param("json_text", HostTypeSchema::String),
            param("pointer", HostTypeSchema::String),
        ],
        public_json_field_type(),
        public_json_field_call,
    )
}

fn envelope(
    kind: &str,
    string_value: Value,
    int_value: Value,
    float_value: Value,
    bool_value: Value,
    length: Value,
) -> Value {
    object(vec![
        ("kind", Value::string(kind)),
        ("string_value", string_value),
        ("int_value", int_value),
        ("float_value", float_value),
        ("bool_value", bool_value),
        ("length", length),
    ])
}

fn empty_envelope(kind: &str) -> Value {
    envelope(
        kind,
        Value::Null,
        Value::Null,
        Value::Null,
        Value::Null,
        Value::Null,
    )
}

fn public_json_field_call(vm: &mut Vm, args: &[Value]) -> VmResult<CallOutcome> {
    let policy_value = args.first().ok_or_else(|| error("invalid_request"))?;
    let owner = super::borrowed::<Policy>(vm, policy_value)?;
    let json_text = super::string(args.get(1).ok_or_else(|| error("invalid_request"))?)?;
    let pointer = super::string(args.get(2).ok_or_else(|| error("invalid_request"))?)?;
    if json_text.len() > MAX_JSON_BYTES {
        return Err(error("public_json_too_large"));
    }
    validate_pointer(pointer)?;
    let parsed = parse_json(json_text, pointer)?;
    validate_depth(&parsed.document, 1)?;
    let selected = resolve_pointer(&parsed.document, &parsed.selected_tokens);
    let output = match selected {
        None => empty_envelope("missing"),
        Some(selected) => {
            if selected.is_number() && parsed.selected_number_out_of_range.get() {
                return Err(error("public_json_number_out_of_range"));
            }
            match selected {
                Json::Null => empty_envelope("null"),
                Json::String(value) => {
                    if value.len() > MAX_JSON_BYTES {
                        return Err(error("public_json_too_large"));
                    }
                    envelope(
                        "string",
                        Value::string(value),
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        Value::Null,
                    )
                }
                Json::Bool(value) => envelope(
                    "bool",
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    Value::Bool(*value),
                    Value::Null,
                ),
                Json::Number(value) => {
                    if let Some(number) = value.as_i64() {
                        envelope(
                            "int",
                            Value::Null,
                            Value::Int(number),
                            Value::Null,
                            Value::Null,
                            Value::Null,
                        )
                    } else if value.is_u64() {
                        return Err(error("public_json_number_out_of_range"));
                    } else {
                        let number = value
                            .as_f64()
                            .filter(|number| number.is_finite())
                            .ok_or_else(|| error("public_json_number_out_of_range"))?;
                        envelope(
                            "float",
                            Value::Null,
                            Value::Null,
                            Value::Float(number),
                            Value::Null,
                            Value::Null,
                        )
                    }
                }
                Json::Object(fields) => {
                    let length = i64::try_from(fields.len())
                        .map_err(|_| error("public_json_number_out_of_range"))?;
                    envelope(
                        "object",
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        Value::Int(length),
                    )
                }
                Json::Array(values) => {
                    let length = i64::try_from(values.len())
                        .map_err(|_| error("public_json_number_out_of_range"))?;
                    envelope(
                        "array",
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        Value::Int(length),
                    )
                }
            }
        }
    };
    owner.check()?;
    result(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unselected_out_of_range_numbers_do_not_retain_source_paths() {
        let one_unselected_number = parse_json(
            r#"{"selected":"public","unrelated":9223372036854775808}"#,
            "/selected",
        )
        .expect("ordinary bounded JSON parses");
        let several_unselected_numbers = parse_json(
            r#"{"selected":"public","unrelated":{"large":9223372036854775808,"tiny":1e-4000,"list":[1e400]}}"#,
            "/selected",
        )
        .expect("ordinary bounded JSON parses");

        assert!(!one_unselected_number.selected_number_out_of_range.get());
        assert!(
            !several_unselected_numbers
                .selected_number_out_of_range
                .get()
        );
        assert_eq!(
            one_unselected_number.selected_tokens,
            several_unselected_numbers.selected_tokens
        );
        assert_eq!(
            one_unselected_number.selected_metadata_storage_bytes,
            several_unselected_numbers.selected_metadata_storage_bytes,
            "unselected numeric nodes changed selected-field metadata storage"
        );
    }
}
