//! Public JSON Schema (Q1/CE1): the schema is generated from the same Rust
//! types the parser accepts, and these tests are the gate that keeps the
//! repository copy and the documented example honest.
//!
//! No JSON Schema validator dependency: the properties asserted here are
//! the ones that matter for drift — every key the documented example uses
//! must exist in the schema, unknown keys must be refused
//! (`additionalProperties: false`, from `deny_unknown_fields`), and a
//! duration must be a string. A validator would only re-check the same
//! facts through a heavier dependency tree.

use std::path::PathBuf;

use serde_json::Value;

fn example_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../eqproxy.toml.example");
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn schema() -> Value {
    serde_json::from_str(
        &eqproxy_config::json_schema().expect("the generated schema renders as JSON"),
    )
    .expect("the schema is JSON")
}

/// `$defs` entry a `$ref` points at (`#/$defs/Name`).
fn ref_name(value: &Value) -> Option<&str> {
    value
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.rsplit('/').next())
}

/// Walks a TOML document against the schema and collects every key path the
/// schema does not know. Mirrors how an editor completes a document: a key
/// missing from `properties` is a key the editor cannot suggest (and the
/// real gate will reject).
fn unknown_keys(
    schema: &Value,
    definition: &str,
    value: &toml::Value,
    path: &str,
    out: &mut Vec<String>,
) {
    let Some(object) = value.as_table() else {
        // Not a table (scalar/array): nothing to walk here. Arrays of tables
        // are walked below with their item schema.
        if let Some(items) = value.as_array() {
            for (index, item) in items.iter().enumerate() {
                if item.is_table() {
                    unknown_keys(schema, definition, item, &format!("{path}[{index}]"), out);
                }
            }
        }
        return;
    };
    // `Config` is the root document; every other definition lives in `$defs`.
    let def = if definition == "Config" {
        schema
    } else {
        let Some(def) = schema.pointer(&format!("/$defs/{definition}")) else {
            out.push(format!("{path}: unknown definition {definition}"));
            return;
        };
        def
    };
    let properties = def.get("properties").and_then(Value::as_object);
    for (key, child) in object {
        let Some(properties) = properties else {
            out.push(format!("{path}.{key}: {definition} has no properties"));
            continue;
        };
        let Some(property) = properties.get(key) else {
            out.push(format!("{path}.{key}: not in the schema"));
            continue;
        };
        // Follow a `$ref` (through `anyOf`, where an Option lives) to the
        // definition of the value, then walk into it.
        let target = property
            .get("anyOf")
            .and_then(Value::as_array)
            .and_then(|options| options.iter().find_map(ref_name))
            .or_else(|| ref_name(property));
        let items_ref = property.get("items").and_then(ref_name).or_else(|| {
            property
                .get("anyOf")
                .and_then(Value::as_array)
                .and_then(|options| {
                    options
                        .iter()
                        .find_map(|option| option.get("items").and_then(ref_name))
                })
        });
        match (target, items_ref, child) {
            (Some(target), _, toml::Value::Table(_) | toml::Value::Array(_)) => {
                unknown_keys(schema, target, child, &format!("{path}.{key}"), out);
            }
            (_, Some(items), toml::Value::Array(entries)) => {
                for (index, entry) in entries.iter().enumerate() {
                    if entry.is_table() {
                        unknown_keys(schema, items, entry, &format!("{path}.{key}[{index}]"), out);
                    }
                }
            }
            _ => {}
        }
    }
}

#[test]
fn the_repository_schema_is_the_generated_one() {
    // Drift gate: `eqproxy config schema --output eqproxy.schema.json`
    // must reproduce the committed file byte for byte. A new config field
    // changes the generated schema, so the file has to be regenerated in
    // the same change — editors never advertise a field the gate rejects.
    let generated = format!(
        "{}\n",
        eqproxy_config::json_schema().expect("the schema renders as JSON")
    );
    assert_eq!(
        eqproxy_config::SCHEMA_FILE,
        generated,
        "eqproxy.schema.json is stale: run `eqproxy config schema --output eqproxy.schema.json`"
    );
}

#[test]
fn the_schema_describes_every_key_of_the_documented_example() {
    let schema = schema();
    let source = example_source();
    let example: toml::Value = toml::from_str(&source).expect("example is valid TOML");
    let mut unknown = Vec::new();
    unknown_keys(&schema, "Config", &example, "", &mut unknown);
    assert!(
        unknown.is_empty(),
        "the documented example uses keys the published schema lacks: {unknown:#?}"
    );

    // And the real parser accepts the same document, so schema and gate
    // agree on it.
    let path = PathBuf::from("eqproxy.toml.example");
    eqproxy_config::parse_str(&source, &path).expect("the example parses");
}

#[test]
fn the_schema_refuses_unknown_keys_and_a_numeric_duration() {
    let schema = schema();
    // `deny_unknown_fields` is published: an editor flags a typo before the
    // gate runs, instead of silently completing a key that cannot work.
    for definition in ["ListenerConfig", "BackendConfig", "RuleConfig"] {
        assert_eq!(
            schema.pointer(&format!("/$defs/{definition}/additionalProperties")),
            Some(&Value::Bool(false)),
            "{definition} must refuse unknown keys"
        );
    }
    assert_eq!(
        schema.pointer("/additionalProperties"),
        Some(&Value::Bool(false)),
        "the top-level document must refuse unknown keys"
    );

    // Durations are human strings (`"5s"`), not serde's default
    // `{ secs, nanos }` object: the schema says what the parser accepts.
    for (definition, field) in [
        ("ListenerConfig", "idle_timeout"),
        ("ListenerConfig", "server_header_timeout"),
        ("BackendConfig", "timeout_queue"),
        // `Config` is the root document, so its properties are top-level.
        ("", "shutdown_grace"),
    ] {
        let pointer = format!("/$defs/{definition}/properties/{field}").replace("/$defs//", "/");
        let property = schema
            .pointer(&pointer)
            .unwrap_or_else(|| panic!("{pointer} must exist"));
        assert_eq!(
            property.get("type").and_then(Value::as_str),
            Some("string"),
            "{definition}.{field} must be typed as a string: {property}"
        );
    }
}

#[test]
fn the_schema_names_every_rule_action() {
    // The rule table is where the features land: a missing property here
    // would hide an action from autocompletion.
    let schema = schema();
    let properties = schema
        .pointer("/$defs/RuleConfig/properties")
        .and_then(Value::as_object)
        .expect("RuleConfig has properties");
    for action in [
        "use_backend",
        "split",
        "hash_policy",
        "request_mirror",
        "redirect",
        "direct_response",
        "rewrite",
        "set_headers",
        "response_headers",
        "auth",
        "cors",
        "rate_limit",
        "map",
    ] {
        assert!(
            properties.contains_key(action),
            "{action} must be in the published schema: {:?}",
            properties.keys().collect::<Vec<_>>()
        );
    }
}
