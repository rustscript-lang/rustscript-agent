use std::{fmt, io};

use serde::{
    Serialize,
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap,
};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_FIELDS: usize = 8;
const MAX_FIELD_NAME_BYTES: usize = 64;

const RESERVED_PUBLIC_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "device_code",
    "device_auth_id",
    "device_id",
    "authorization_code",
    "code_verifier",
    "verifier",
    "client_secret",
    "password",
    "api_key",
    "authorization",
    "cookie",
    "code",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBodyEncoding {
    Form,
    JsonObject,
}

impl RequestBodyEncoding {
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Form => "application/x-www-form-urlencoded",
            Self::JsonObject => "application/json",
        }
    }
}

pub struct SecretField {
    name: String,
    value: Zeroizing<String>,
}

impl SecretField {
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, RequestBodyError> {
        let name = name.into();
        let value = Zeroizing::new(value.into());

        if !is_valid_field_name(&name) {
            return Err(RequestBodyError::InvalidFieldName);
        }
        if value.is_empty() {
            return Err(RequestBodyError::EmptySecret);
        }
        if value.len() > MAX_BODY_BYTES {
            return Err(RequestBodyError::SecretTooLarge);
        }
        if value.contains('\0') {
            return Err(RequestBodyError::SecretContainsNul);
        }

        Ok(Self { name, value })
    }
}

impl fmt::Debug for SecretField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretField")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

pub struct SecretRequestBody {
    body: Zeroizing<String>,
}

impl SecretRequestBody {
    pub fn as_str_for_transport(&self) -> &str {
        self.body.as_str()
    }
}

impl fmt::Debug for SecretRequestBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRequestBody")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBodyError {
    InputTooLarge,
    OutputTooLarge,
    TooManyFields,
    InvalidFieldName,
    EmptySecret,
    SecretTooLarge,
    SecretContainsNul,
    DuplicateInjectedField,
    InvalidFormEncoding,
    InvalidFormUtf8,
    EmptyFormKey,
    DuplicatePublicKey,
    ReservedPublicKey,
    InvalidJson,
    DuplicateJsonKey,
    JsonTopLevelNotObject,
    JsonDepthExceeded,
}

impl fmt::Display for RequestBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InputTooLarge => "public request body exceeds the size limit",
            Self::OutputTooLarge => "encoded request body exceeds the size limit",
            Self::TooManyFields => "too many injected secret fields",
            Self::InvalidFieldName => "invalid secret field name",
            Self::EmptySecret => "secret field value must not be empty",
            Self::SecretTooLarge => "secret field value exceeds the size limit",
            Self::SecretContainsNul => "secret field value contains a NUL byte",
            Self::DuplicateInjectedField => "duplicate injected secret field name",
            Self::InvalidFormEncoding => "invalid form percent encoding",
            Self::InvalidFormUtf8 => "form data is not valid UTF-8",
            Self::EmptyFormKey => "form field name must not be empty",
            Self::DuplicatePublicKey => "duplicate public field name",
            Self::ReservedPublicKey => "public body contains a reserved field name",
            Self::InvalidJson => "invalid JSON request body",
            Self::DuplicateJsonKey => "duplicate JSON object key",
            Self::JsonTopLevelNotObject => "JSON request body must be an object",
            Self::JsonDepthExceeded => "JSON request body exceeds the nesting limit",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RequestBodyError {}

pub fn encode_injected_body(
    public_body: &str,
    encoding: RequestBodyEncoding,
    fields: &[SecretField],
) -> Result<SecretRequestBody, RequestBodyError> {
    if public_body.len() > MAX_BODY_BYTES {
        return Err(RequestBodyError::InputTooLarge);
    }
    validate_fields(fields)?;

    match encoding {
        RequestBodyEncoding::Form => encode_form(public_body, fields),
        RequestBodyEncoding::JsonObject => encode_json_object(public_body, fields),
    }
}

fn validate_fields(fields: &[SecretField]) -> Result<(), RequestBodyError> {
    if fields.len() > MAX_FIELDS {
        return Err(RequestBodyError::TooManyFields);
    }

    for (index, field) in fields.iter().enumerate() {
        if !is_valid_field_name(&field.name) {
            return Err(RequestBodyError::InvalidFieldName);
        }
        if field.value.is_empty() {
            return Err(RequestBodyError::EmptySecret);
        }
        if field.value.len() > MAX_BODY_BYTES {
            return Err(RequestBodyError::SecretTooLarge);
        }
        if field.value.contains('\0') {
            return Err(RequestBodyError::SecretContainsNul);
        }
        if fields[..index]
            .iter()
            .any(|previous| previous.name.eq_ignore_ascii_case(&field.name))
        {
            return Err(RequestBodyError::DuplicateInjectedField);
        }
    }
    Ok(())
}

fn is_valid_field_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_FIELD_NAME_BYTES {
        return false;
    }

    let first = bytes[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
}

fn is_reserved_public_key(name: &str, fields: &[SecretField]) -> bool {
    RESERVED_PUBLIC_KEYS
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
        || fields
            .iter()
            .any(|field| name.eq_ignore_ascii_case(&field.name))
}

fn encode_form(
    public_body: &str,
    fields: &[SecretField],
) -> Result<SecretRequestBody, RequestBodyError> {
    let pairs = parse_form(public_body, fields)?;
    let mut body = Zeroizing::new(String::new());

    for (key, value) in &pairs {
        append_form_pair(&mut body, key, value)?;
    }
    for field in fields {
        append_form_pair(&mut body, &field.name, field.value.as_str())?;
    }

    Ok(SecretRequestBody { body })
}

fn parse_form(
    public_body: &str,
    fields: &[SecretField],
) -> Result<Vec<(String, String)>, RequestBodyError> {
    if public_body.is_empty() {
        return Ok(Vec::new());
    }

    let mut pairs: Vec<(String, String)> = Vec::new();
    for segment in public_body.split('&') {
        let (encoded_key, encoded_value) = segment.split_once('=').unwrap_or((segment, ""));
        let key = decode_form_component(encoded_key)?;
        if key.is_empty() {
            return Err(RequestBodyError::EmptyFormKey);
        }
        if pairs
            .iter()
            .any(|(previous, _)| previous.eq_ignore_ascii_case(&key))
        {
            return Err(RequestBodyError::DuplicatePublicKey);
        }
        if is_reserved_public_key(&key, fields) {
            return Err(RequestBodyError::ReservedPublicKey);
        }
        let value = decode_form_component(encoded_value)?;
        pairs.push((key, value));
    }
    Ok(pairs)
}

fn decode_form_component(component: &str) -> Result<String, RequestBodyError> {
    let bytes = component.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(RequestBodyError::InvalidFormEncoding);
                }
                let Some(high) = hex_value(bytes[index + 1]) else {
                    return Err(RequestBodyError::InvalidFormEncoding);
                };
                let Some(low) = hex_value(bytes[index + 2]) else {
                    return Err(RequestBodyError::InvalidFormEncoding);
                };
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| RequestBodyError::InvalidFormUtf8)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn append_form_pair(
    output: &mut Zeroizing<String>,
    key: &str,
    value: &str,
) -> Result<(), RequestBodyError> {
    if !output.is_empty() {
        append_bounded(output, "&")?;
    }
    append_form_component(output, key)?;
    append_bounded(output, "=")?;
    append_form_component(output, value)
}

fn append_form_component(
    output: &mut Zeroizing<String>,
    value: &str,
) -> Result<(), RequestBodyError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            if output.len() == MAX_BODY_BYTES {
                return Err(RequestBodyError::OutputTooLarge);
            }
            output.push(char::from(*byte));
        } else {
            let encoded = [
                b'%',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 0x0f)],
            ];
            append_bounded(
                output,
                std::str::from_utf8(&encoded).expect("ASCII encoding"),
            )?;
        }
    }
    Ok(())
}

fn append_bounded(output: &mut Zeroizing<String>, value: &str) -> Result<(), RequestBodyError> {
    if output.len().saturating_add(value.len()) > MAX_BODY_BYTES {
        return Err(RequestBodyError::OutputTooLarge);
    }
    output.push_str(value);
    Ok(())
}

const MAX_JSON_DEPTH: usize = 8;
const JSON_DEPTH_MARKER: &str = "request_body_json_depth_limit";
const JSON_DUPLICATE_MARKER: &str = "request_body_duplicate_json_key";

fn encode_json_object(
    public_body: &str,
    fields: &[SecretField],
) -> Result<SecretRequestBody, RequestBodyError> {
    let public_value = if public_body.is_empty() {
        Value::Object(Map::new())
    } else {
        parse_json_value(public_body)?
    };
    let public_object = match &public_value {
        Value::Object(object) => object,
        _ => return Err(RequestBodyError::JsonTopLevelNotObject),
    };
    validate_json_keys(&public_value, fields)?;

    let mut encoded = Zeroizing::new(Vec::with_capacity(public_body.len().min(MAX_BODY_BYTES)));
    let serialization = {
        let mut writer = BoundedJsonWriter {
            encoded: &mut encoded,
            exceeded: false,
        };
        let result = serde_json::to_writer(
            &mut writer,
            &JsonObjectWithSecrets {
                public: public_object,
                fields,
            },
        );
        (result, writer.exceeded)
    };

    if serialization.1 {
        return Err(RequestBodyError::OutputTooLarge);
    }
    serialization.0.map_err(|_| RequestBodyError::InvalidJson)?;

    let serialized =
        std::str::from_utf8(encoded.as_slice()).map_err(|_| RequestBodyError::InvalidJson)?;
    let body = Zeroizing::new(serialized.to_owned());
    Ok(SecretRequestBody { body })
}

fn parse_json_value(public_body: &str) -> Result<Value, RequestBodyError> {
    let mut deserializer = serde_json::Deserializer::from_str(public_body);
    let value = match (JsonValueSeed { depth: 0 }).deserialize(&mut deserializer) {
        Ok(value) => value,
        Err(error) => {
            let message = error.to_string();
            if message.contains(JSON_DEPTH_MARKER) {
                return Err(RequestBodyError::JsonDepthExceeded);
            }
            if message.contains(JSON_DUPLICATE_MARKER) {
                return Err(RequestBodyError::DuplicateJsonKey);
            }
            return Err(RequestBodyError::InvalidJson);
        }
    };
    deserializer
        .end()
        .map_err(|_| RequestBodyError::InvalidJson)?;
    Ok(value)
}

fn validate_json_keys(value: &Value, fields: &[SecretField]) -> Result<(), RequestBodyError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if is_reserved_public_key(key, fields) {
                    return Err(RequestBodyError::ReservedPublicKey);
                }
                validate_json_keys(nested, fields)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                validate_json_keys(nested, fields)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct JsonValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for JsonValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonValueVisitor { depth: self.depth })
    }
}

struct JsonValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for JsonValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value within the configured nesting limit")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(serde::de::Error::custom(JSON_DEPTH_MARKER));
        }
        let child_depth = self.depth + 1;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonValueSeed { depth: child_depth })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(serde::de::Error::custom(JSON_DEPTH_MARKER));
        }
        let child_depth = self.depth + 1;
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(JSON_DUPLICATE_MARKER));
            }
            let value = map.next_value_seed(JsonValueSeed { depth: child_depth })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct JsonObjectWithSecrets<'a> {
    public: &'a Map<String, Value>,
    fields: &'a [SecretField],
}

impl Serialize for JsonObjectWithSecrets<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut object =
            serializer.serialize_map(Some(self.public.len().saturating_add(self.fields.len())))?;
        for (key, value) in self.public {
            object.serialize_entry(key, value)?;
        }
        for field in self.fields {
            object.serialize_entry(&field.name, field.value.as_str())?;
        }
        object.end()
    }
}

struct BoundedJsonWriter<'a> {
    encoded: &'a mut Zeroizing<Vec<u8>>,
    exceeded: bool,
}

impl io::Write for BoundedJsonWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.encoded.len().saturating_add(bytes.len()) > MAX_BODY_BYTES {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "encoded request body exceeds the size limit",
            ));
        }
        self.encoded.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
