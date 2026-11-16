//! Unwrap frozen-core SQLite named-struct rows into the storage protocol's
//! primitive cell arrays.
//!
//! `sqlite::query` now returns `SqliteQueryResult { rows: [{ cells: [SqliteValue] }] }`.
//! Gateway/service readers still consume `data.rows` as arrays of JSON primitives.

use serde_json::Value;

pub fn sqlite_storage_rows(data: &Value) -> Result<Vec<Vec<Value>>, String> {
    if let Some(rows) = data.get("rows") {
        return sqlite_storage_row_list(rows);
    }
    if data.as_array().is_some() {
        return sqlite_storage_row_list(data);
    }
    Err("storage result omitted rows".to_string())
}

pub fn sqlite_storage_row_list(value: &Value) -> Result<Vec<Vec<Value>>, String> {
    let rows = value
        .as_array()
        .ok_or_else(|| "storage rows value is not an array".to_string())?;
    rows.iter().map(sqlite_storage_row).collect()
}

pub fn sqlite_storage_first_row(data: &Value) -> Option<Vec<Value>> {
    sqlite_storage_rows(data).ok()?.into_iter().next()
}

pub fn sqlite_storage_row(row: &Value) -> Result<Vec<Value>, String> {
    if let Some(cells) = row.get("cells").and_then(Value::as_array) {
        return cells.iter().map(sqlite_storage_cell).collect();
    }
    let Some(arr) = row.as_array() else {
        return Err("storage row is not an array or SqliteRow".to_string());
    };
    arr.iter().map(sqlite_storage_cell).collect()
}

pub fn sqlite_storage_cell(value: &Value) -> Result<Value, String> {
    let Some(obj) = value.as_object() else {
        return Ok(value.clone());
    };
    let Some(kind) = obj.get("kind").and_then(Value::as_str) else {
        return Ok(value.clone());
    };
    let cell = match kind {
        "int" => carried(&obj.get("int_value").cloned().unwrap_or(Value::Null)),
        "float" => carried(&obj.get("float_value").cloned().unwrap_or(Value::Null)),
        "text" => carried(&obj.get("text_value").cloned().unwrap_or(Value::Null)),
        "blob" => carried(&obj.get("blob_value").cloned().unwrap_or(Value::Null)),
        "null" => Value::Null,
        _ => value.clone(),
    };
    Ok(cell)
}

/// Unwraps a logical `Option` carrier into the plain value it holds.
///
/// The strict guest dialect cannot spell a null literal, so a `SqliteValue`
/// leaf that is absent arrives as `{tag: false}` and a present one as
/// `{tag: true, payload: value}`. Row consumers expect the plain value.
fn carried(value: &Value) -> Value {
    let Some(obj) = value.as_object() else {
        return value.clone();
    };
    match obj.get("tag") {
        Some(Value::Bool(true)) => obj.get("payload").cloned().unwrap_or(Value::Null),
        Some(Value::Bool(false)) if obj.len() == 1 => Value::Null,
        _ => value.clone(),
    }
}
