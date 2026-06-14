//! JSON path resolution.
//!
//! Resolves dot-notation paths like "csdma.plausibility_score" to values in JSON.

use serde_json::Value;

/// Resolve a dot-notation path to a value in JSON.
///
/// # Examples
/// ```
/// use serde_json::json;
/// let data = json!({"csdma": {"plausibility_score": 0.95}});
/// let value = resolve_json_path(&data, "csdma.plausibility_score");
/// assert_eq!(value, Some(&json!(0.95)));
/// ```
pub fn resolve_json_path<'a>(data: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(data);
    }

    let mut current = data;
    for part in path.split('.') {
        match current {
            Value::Object(obj) => {
                current = obj.get(part)?;
            }
            Value::Array(arr) => {
                // Support array indexing like "items.0.name"
                let index: usize = part.parse().ok()?;
                current = arr.get(index)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

/// Convert a JSON value to a string representation for database storage.
pub fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => value.to_string(), // Arrays and objects as JSON strings
    }
}

/// Convert a JSON value to a float if possible.
pub fn value_to_float(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Convert a JSON value to an integer if possible.
pub fn value_to_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Convert a JSON value to a boolean if possible.
pub fn value_to_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        Value::Number(n) => n.as_i64().map(|i| i != 0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_simple_path() {
        let data = json!({"name": "test"});
        assert_eq!(resolve_json_path(&data, "name"), Some(&json!("test")));
    }

    #[test]
    fn test_nested_path() {
        let data = json!({
            "csdma": {
                "plausibility_score": 0.95,
                "confidence": 0.8
            }
        });
        assert_eq!(
            resolve_json_path(&data, "csdma.plausibility_score"),
            Some(&json!(0.95))
        );
    }

    #[test]
    fn test_deep_nested_path() {
        let data = json!({
            "system_snapshot": {
                "agent_profile": {
                    "name": "TestAgent"
                }
            }
        });
        assert_eq!(
            resolve_json_path(&data, "system_snapshot.agent_profile.name"),
            Some(&json!("TestAgent"))
        );
    }

    #[test]
    fn test_array_index() {
        let data = json!({
            "items": [
                {"name": "first"},
                {"name": "second"}
            ]
        });
        assert_eq!(
            resolve_json_path(&data, "items.0.name"),
            Some(&json!("first"))
        );
        assert_eq!(
            resolve_json_path(&data, "items.1.name"),
            Some(&json!("second"))
        );
    }

    #[test]
    fn test_missing_path() {
        let data = json!({"name": "test"});
        assert_eq!(resolve_json_path(&data, "missing"), None);
        assert_eq!(resolve_json_path(&data, "name.nested"), None);
    }

    #[test]
    fn test_empty_path() {
        let data = json!({"name": "test"});
        assert_eq!(resolve_json_path(&data, ""), Some(&data));
    }

    #[test]
    fn test_value_conversions() {
        assert_eq!(value_to_float(&json!(1.5)), Some(1.5));
        assert_eq!(value_to_float(&json!("2.5")), Some(2.5));
        assert_eq!(value_to_int(&json!(42)), Some(42));
        assert_eq!(value_to_bool(&json!(true)), Some(true));
        assert_eq!(value_to_bool(&json!("true")), Some(true));
        assert_eq!(value_to_bool(&json!(1)), Some(true));
    }
}
