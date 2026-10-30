//! Find things in a pushed view, without depending on where they sit in the tree.

use serde_json::Value;

/// Every `row_keys` entry in a view.
pub fn row_keys(view: &Value) -> Vec<String> {
    let mut out = vec![];
    walk(view, &mut |node| {
        if let Some(keys) = node.get("row_keys").and_then(Value::as_array) {
            out.extend(keys.iter().filter_map(|k| k.as_str().map(str::to_string)));
        }
    });
    out
}

/// The row keys of the first table that has `column` among its columns.
pub fn row_keys_of_table_with(view: &Value, column: &str) -> Vec<String> {
    first_table_with(view, column)
        .and_then(|t| t.get("row_keys"))
        .and_then(Value::as_array)
        .map(|keys| keys.iter().filter_map(|k| k.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// The rows of the first table that has `column` among its columns, as text.
pub fn rows_of_table_with(view: &Value, column: &str) -> Vec<Vec<String>> {
    first_table_with(view, column)
        .and_then(|t| t.get("rows"))
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    row.as_array()
                        .map(|cells| cells.iter().map(|c| c.as_str().unwrap_or_default().to_string()).collect())
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Every component of one `type` (`"select"`, `"field"`, …).
pub fn components_of_type(view: &Value, kind: &str) -> Vec<Value> {
    let mut out = vec![];
    walk(view, &mut |node| {
        if node.get("type").and_then(Value::as_str) == Some(kind) {
            out.push(node.clone());
        }
    });
    out
}

fn first_table_with<'a>(view: &'a Value, column: &str) -> Option<&'a Value> {
    match view {
        Value::Object(map) => {
            let has_column = map
                .get("columns")
                .and_then(Value::as_array)
                .is_some_and(|cols| cols.iter().any(|c| c.as_str() == Some(column)));
            if has_column {
                return Some(view);
            }
            map.values().find_map(|child| first_table_with(child, column))
        }
        Value::Array(items) => items.iter().find_map(|item| first_table_with(item, column)),
        _ => None,
    }
}

fn walk(view: &Value, visit: &mut impl FnMut(&Value)) {
    visit(view);
    match view {
        Value::Object(map) => map.values().for_each(|child| walk(child, visit)),
        Value::Array(items) => items.iter().for_each(|item| walk(item, visit)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn view() -> Value {
        json!({ "type": "stack", "children": [
            { "type": "select", "id": "a" },
            { "type": "table", "columns": ["name"], "rows": [["one"]], "row_keys": ["k1"] },
            { "type": "table", "columns": ["run"], "rows": [["two", "x"]], "row_keys": ["k2"] },
        ]})
    }

    #[test]
    fn finds_tables_rows_and_components() {
        let v = view();
        assert_eq!(row_keys(&v), vec!["k1", "k2"]);
        assert_eq!(row_keys_of_table_with(&v, "run"), vec!["k2"]);
        assert_eq!(rows_of_table_with(&v, "run"), vec![vec!["two".to_string(), "x".to_string()]]);
        assert!(rows_of_table_with(&v, "nothing").is_empty());
        assert_eq!(components_of_type(&v, "select").len(), 1);
    }
}
