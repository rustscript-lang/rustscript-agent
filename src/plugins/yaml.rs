//! Strict YAML subset for plugin contracts.
//!
//! Aliases, tags, merge keys, and duplicate fields are rejected before any
//! JSON value is produced. This parser never fetches a schema or a remote URI.

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use yaml_rust2::parser::{Event, EventReceiver, Parser};
use yaml_rust2::scanner::TScalarStyle;

use super::error::{PluginError, PluginErrorKind};

struct StrictLoader {
    stack: Vec<Frame>,
    error: Option<PluginError>,
    docs: Vec<Value>,
}

enum Frame {
    Map {
        values: Map<String, Value>,
        key: Option<String>,
    },
    Seq(Vec<Value>),
}

impl StrictLoader {
    fn fail(&mut self, kind: PluginErrorKind) {
        if self.error.is_none() {
            self.error = Some(PluginError::new(kind, kind_label(kind)));
        }
    }

    fn insert(&mut self, value: Value) {
        if self.error.is_some() {
            return;
        }
        if self.stack.is_empty() {
            self.docs.push(value);
            return;
        }
        match self.stack.last_mut() {
            Some(Frame::Seq(items)) => items.push(value),
            Some(Frame::Map { values, key }) => {
                let Some(key) = key.take() else {
                    self.error = Some(PluginError::new(
                        PluginErrorKind::UnknownField,
                        "mapping value without key",
                    ));
                    return;
                };
                if key == "<<" {
                    self.error = Some(PluginError::new(PluginErrorKind::YamlMerge, "merge key"));
                    return;
                }
                if values.contains_key(&key) {
                    self.error = Some(PluginError::new(PluginErrorKind::DuplicateField, key));
                    return;
                }
                values.insert(key, value);
            }
            None => self.docs.push(value),
        }
    }
}

impl EventReceiver for StrictLoader {
    fn on_event(&mut self, ev: Event) {
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::StreamStart | Event::StreamEnd | Event::DocumentStart | Event::Nothing => {}
            Event::DocumentEnd => {
                if self.stack.len() == 1 {
                    let frame = self.stack.pop().unwrap();
                    let value = match frame {
                        Frame::Map { values, key } if key.is_none() => Value::Object(values),
                        Frame::Seq(items) => Value::Array(items),
                        _ => {
                            self.fail(PluginErrorKind::UnknownField);
                            return;
                        }
                    };
                    self.docs.push(value);
                } else if !self.stack.is_empty() {
                    self.fail(PluginErrorKind::UnknownField);
                }
            }
            Event::Alias(_) => self.fail(PluginErrorKind::YamlAlias),
            Event::SequenceStart(anchor, tag) => {
                if anchor != 0 {
                    self.fail(PluginErrorKind::YamlAlias);
                    return;
                }
                if tag.is_some() {
                    self.fail(PluginErrorKind::YamlTag);
                    return;
                }
                self.stack.push(Frame::Seq(Vec::new()));
            }
            Event::SequenceEnd => {
                let Some(Frame::Seq(items)) = self.stack.pop() else {
                    self.fail(PluginErrorKind::UnknownField);
                    return;
                };
                self.insert(Value::Array(items));
            }
            Event::MappingStart(anchor, tag) => {
                if anchor != 0 {
                    self.fail(PluginErrorKind::YamlAlias);
                    return;
                }
                if tag.is_some() {
                    self.fail(PluginErrorKind::YamlTag);
                    return;
                }
                self.stack.push(Frame::Map {
                    values: Map::new(),
                    key: None,
                });
            }
            Event::MappingEnd => {
                let Some(Frame::Map { values, key }) = self.stack.pop() else {
                    self.fail(PluginErrorKind::UnknownField);
                    return;
                };
                if key.is_some() {
                    self.fail(PluginErrorKind::UnknownField);
                    return;
                }
                self.insert(Value::Object(values));
            }
            Event::Scalar(text, style, anchor, tag) => {
                if anchor != 0 {
                    self.fail(PluginErrorKind::YamlAlias);
                    return;
                }
                if tag.is_some() {
                    self.fail(PluginErrorKind::YamlTag);
                    return;
                }
                if let Some(Frame::Map { key, .. }) = self.stack.last_mut()
                    && key.is_none()
                {
                    if text == "<<" {
                        self.fail(PluginErrorKind::YamlMerge);
                        return;
                    }
                    *key = Some(text);
                    return;
                }
                self.insert(scalar_value(&text, style));
            }
        }
    }
}

fn scalar_value(text: &str, style: TScalarStyle) -> Value {
    if style != TScalarStyle::Plain {
        return Value::String(text.to_string());
    }
    match text {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "~" | "null" | "Null" | "NULL" => Value::Null,
        _ => {
            if text.bytes().all(|byte| byte.is_ascii_digit())
                && let Ok(number) = text.parse::<i64>()
            {
                return Value::Number(number.into());
            }
            Value::String(text.to_string())
        }
    }
}

fn kind_label(kind: PluginErrorKind) -> &'static str {
    match kind {
        PluginErrorKind::YamlAlias => "yaml alias",
        PluginErrorKind::YamlTag => "yaml tag",
        PluginErrorKind::YamlMerge => "yaml merge",
        PluginErrorKind::DuplicateField => "duplicate field",
        PluginErrorKind::UnknownField => "unknown field",
        _ => "yaml",
    }
}

pub fn strict_yaml_to_json(text: &str) -> Result<Value, PluginError> {
    let mut loader = StrictLoader {
        stack: Vec::new(),
        error: None,
        docs: Vec::new(),
    };
    let mut parser = Parser::new_from_str(text);
    if let Err(error) = parser.load(&mut loader, false) {
        if let Some(parsed) = loader.error {
            return Err(parsed);
        }
        let message = error.to_string();
        let kind = if message.contains("alias") || message.contains("anchor") {
            PluginErrorKind::YamlAlias
        } else if message.contains("tag") {
            PluginErrorKind::YamlTag
        } else {
            PluginErrorKind::UnknownField
        };
        return Err(PluginError::new(kind, "yaml syntax"));
    }
    if let Some(error) = loader.error {
        return Err(error);
    }
    if loader.docs.len() != 1 {
        return Err(PluginError::new(
            PluginErrorKind::UnknownField,
            "exactly one yaml document",
        ));
    }
    let value = loader.docs.pop().unwrap();
    if value.is_null() {
        return Err(PluginError::new(
            PluginErrorKind::UnknownField,
            "null document",
        ));
    }
    reject_nulls(&value)?;
    Ok(value)
}

fn reject_nulls(value: &Value) -> Result<(), PluginError> {
    match value {
        Value::Null => Err(PluginError::new(PluginErrorKind::UnknownField, "null")),
        Value::Array(items) => items.iter().try_for_each(reject_nulls),
        Value::Object(map) => {
            let mut seen = BTreeSet::new();
            for (key, child) in map {
                if !seen.insert(key) {
                    return Err(PluginError::new(
                        PluginErrorKind::DuplicateField,
                        key.clone(),
                    ));
                }
                reject_nulls(child)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
