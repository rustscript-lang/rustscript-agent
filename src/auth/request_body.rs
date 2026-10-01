use std::{
    collections::HashSet,
    fmt,
    io::{self, Write},
};

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

enum JsonPublicValue<'a> {
    Scalar(&'a str),
    Array(Vec<JsonPublicValue<'a>>),
    Object(Vec<(String, JsonPublicValue<'a>)>),
}

struct JsonParser<'a> {
    input: &'a str,
    cursor: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, cursor: 0 }
    }

    fn parse_document(mut self) -> Result<JsonPublicValue<'a>, RequestBodyError> {
        self.skip_whitespace();
        let value = self.parse_value(0)?;
        self.skip_whitespace();
        if self.cursor != self.input.len() {
            return Err(RequestBodyError::InvalidJson);
        }
        Ok(value)
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonPublicValue<'a>, RequestBodyError> {
        match self.peek_byte() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(JsonPublicValue::Scalar(self.parse_string_token()?)),
            Some(b't') => Ok(JsonPublicValue::Scalar(self.parse_literal("true")?)),
            Some(b'f') => Ok(JsonPublicValue::Scalar(self.parse_literal("false")?)),
            Some(b'n') => Ok(JsonPublicValue::Scalar(self.parse_literal("null")?)),
            Some(b'-' | b'0'..=b'9') => Ok(JsonPublicValue::Scalar(self.parse_number_token()?)),
            _ => Err(RequestBodyError::InvalidJson),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonPublicValue<'a>, RequestBodyError> {
        if depth >= MAX_JSON_DEPTH {
            return Err(RequestBodyError::JsonDepthExceeded);
        }
        self.cursor += 1;
        self.skip_whitespace();
        if self.peek_byte() == Some(b'}') {
            self.cursor += 1;
            return Ok(JsonPublicValue::Object(Vec::new()));
        }

        let mut seen_keys = HashSet::new();
        let mut entries = Vec::new();
        loop {
            let raw_key = self.parse_string_token()?;
            let key = serde_json::from_str::<String>(raw_key)
                .map_err(|_| RequestBodyError::InvalidJson)?;
            if !seen_keys.insert(key.clone()) {
                return Err(RequestBodyError::DuplicateJsonKey);
            }
            self.skip_whitespace();
            if self.peek_byte() != Some(b':') {
                return Err(RequestBodyError::InvalidJson);
            }
            self.cursor += 1;
            self.skip_whitespace();
            let value = self.parse_value(depth + 1)?;
            entries.push((key, value));
            self.skip_whitespace();
            match self.peek_byte() {
                Some(b',') => {
                    self.cursor += 1;
                    self.skip_whitespace();
                }
                Some(b'}') => {
                    self.cursor += 1;
                    break;
                }
                _ => return Err(RequestBodyError::InvalidJson),
            }
        }
        Ok(JsonPublicValue::Object(entries))
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonPublicValue<'a>, RequestBodyError> {
        if depth >= MAX_JSON_DEPTH {
            return Err(RequestBodyError::JsonDepthExceeded);
        }
        self.cursor += 1;
        self.skip_whitespace();
        if self.peek_byte() == Some(b']') {
            self.cursor += 1;
            return Ok(JsonPublicValue::Array(Vec::new()));
        }

        let mut values = Vec::new();
        loop {
            values.push(self.parse_value(depth + 1)?);
            self.skip_whitespace();
            match self.peek_byte() {
                Some(b',') => {
                    self.cursor += 1;
                    self.skip_whitespace();
                }
                Some(b']') => {
                    self.cursor += 1;
                    break;
                }
                _ => return Err(RequestBodyError::InvalidJson),
            }
        }
        Ok(JsonPublicValue::Array(values))
    }

    fn parse_string_token(&mut self) -> Result<&'a str, RequestBodyError> {
        if self.peek_byte() != Some(b'"') {
            return Err(RequestBodyError::InvalidJson);
        }
        let start = self.cursor;
        self.cursor += 1;
        while let Some(byte) = self.peek_byte() {
            match byte {
                b'"' => {
                    self.cursor += 1;
                    let token = self
                        .input
                        .get(start..self.cursor)
                        .ok_or(RequestBodyError::InvalidJson)?;
                    serde_json::from_str::<String>(token)
                        .map_err(|_| RequestBodyError::InvalidJson)?;
                    return Ok(token);
                }
                b'\\' => {
                    self.cursor += 1;
                    if self.cursor == self.input.len() {
                        return Err(RequestBodyError::InvalidJson);
                    }
                    self.cursor += 1;
                }
                0x00..=0x1f => return Err(RequestBodyError::InvalidJson),
                _ => self.cursor += 1,
            }
        }
        Err(RequestBodyError::InvalidJson)
    }

    fn parse_literal(&mut self, expected: &'static str) -> Result<&'a str, RequestBodyError> {
        let start = self.cursor;
        if !self
            .input
            .get(self.cursor..)
            .is_some_and(|remaining| remaining.starts_with(expected))
        {
            return Err(RequestBodyError::InvalidJson);
        }
        self.cursor += expected.len();
        self.input
            .get(start..self.cursor)
            .ok_or(RequestBodyError::InvalidJson)
    }

    fn parse_number_token(&mut self) -> Result<&'a str, RequestBodyError> {
        let start = self.cursor;
        if self.peek_byte() == Some(b'-') {
            self.cursor += 1;
        }

        match self.peek_byte() {
            Some(b'0') => {
                self.cursor += 1;
                if matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    return Err(RequestBodyError::InvalidJson);
                }
            }
            Some(b'1'..=b'9') => {
                self.cursor += 1;
                while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    self.cursor += 1;
                }
            }
            _ => return Err(RequestBodyError::InvalidJson),
        }

        if self.peek_byte() == Some(b'.') {
            self.cursor += 1;
            let fraction_start = self.cursor;
            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.cursor += 1;
            }
            if self.cursor == fraction_start {
                return Err(RequestBodyError::InvalidJson);
            }
        }

        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.cursor += 1;
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.cursor += 1;
            }
            let exponent_start = self.cursor;
            while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                self.cursor += 1;
            }
            if self.cursor == exponent_start {
                return Err(RequestBodyError::InvalidJson);
            }
        }

        self.input
            .get(start..self.cursor)
            .ok_or(RequestBodyError::InvalidJson)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.cursor += 1;
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.cursor).copied()
    }
}

fn encode_json_object(
    public_body: &str,
    fields: &[SecretField],
) -> Result<SecretRequestBody, RequestBodyError> {
    let public_value = if public_body.is_empty() {
        JsonPublicValue::Object(Vec::new())
    } else {
        JsonParser::new(public_body).parse_document()?
    };
    let public_object = match &public_value {
        JsonPublicValue::Object(object) => object,
        _ => return Err(RequestBodyError::JsonTopLevelNotObject),
    };
    validate_json_keys(&public_value, fields)?;

    let mut encoded = Zeroizing::new(Vec::with_capacity(public_body.len().min(MAX_BODY_BYTES)));
    let serialization = {
        let mut writer = BoundedJsonWriter {
            encoded: &mut encoded,
            exceeded: false,
        };
        let result = write_json_object(&mut writer, public_object, fields);
        (result, writer.exceeded)
    };

    if serialization.1 {
        return Err(RequestBodyError::OutputTooLarge);
    }
    serialization.0?;

    let serialized =
        std::str::from_utf8(encoded.as_slice()).map_err(|_| RequestBodyError::InvalidJson)?;
    let body = Zeroizing::new(serialized.to_owned());
    Ok(SecretRequestBody { body })
}

fn validate_json_keys(
    value: &JsonPublicValue<'_>,
    fields: &[SecretField],
) -> Result<(), RequestBodyError> {
    match value {
        JsonPublicValue::Object(object) => {
            for (key, nested) in object {
                if is_reserved_public_key(key, fields) {
                    return Err(RequestBodyError::ReservedPublicKey);
                }
                validate_json_keys(nested, fields)?;
            }
        }
        JsonPublicValue::Array(values) => {
            for nested in values {
                validate_json_keys(nested, fields)?;
            }
        }
        JsonPublicValue::Scalar(_) => {}
    }
    Ok(())
}

fn write_json_object(
    writer: &mut BoundedJsonWriter<'_>,
    public: &[(String, JsonPublicValue<'_>)],
    fields: &[SecretField],
) -> Result<(), RequestBodyError> {
    write_json_bytes(writer, b"{")?;
    let mut first = true;
    for (key, value) in public {
        if !first {
            write_json_bytes(writer, b",")?;
        }
        write_json_string(writer, key)?;
        write_json_bytes(writer, b":")?;
        write_json_value(writer, value)?;
        first = false;
    }
    for field in fields {
        if !first {
            write_json_bytes(writer, b",")?;
        }
        write_json_string(writer, &field.name)?;
        write_json_bytes(writer, b":")?;
        write_json_string(writer, field.value.as_str())?;
        first = false;
    }
    write_json_bytes(writer, b"}")
}

fn write_json_value(
    writer: &mut BoundedJsonWriter<'_>,
    value: &JsonPublicValue<'_>,
) -> Result<(), RequestBodyError> {
    match value {
        JsonPublicValue::Scalar(token) => write_json_bytes(writer, token.as_bytes()),
        JsonPublicValue::Array(values) => {
            write_json_bytes(writer, b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    write_json_bytes(writer, b",")?;
                }
                write_json_value(writer, value)?;
            }
            write_json_bytes(writer, b"]")
        }
        JsonPublicValue::Object(entries) => write_json_object(writer, entries, &[]),
    }
}

fn write_json_string(
    writer: &mut BoundedJsonWriter<'_>,
    value: &str,
) -> Result<(), RequestBodyError> {
    if serde_json::to_writer(&mut *writer, value).is_err() {
        return Err(writer.failure());
    }
    Ok(())
}

fn write_json_bytes(
    writer: &mut BoundedJsonWriter<'_>,
    bytes: &[u8],
) -> Result<(), RequestBodyError> {
    if writer.write_all(bytes).is_err() {
        return Err(writer.failure());
    }
    Ok(())
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

impl BoundedJsonWriter<'_> {
    fn failure(&self) -> RequestBodyError {
        if self.exceeded {
            RequestBodyError::OutputTooLarge
        } else {
            RequestBodyError::InvalidJson
        }
    }
}
