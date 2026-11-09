//! Which properties of a request fail the shape of its DTO, named the way the wire names them
//! (layer: HTTP adapter).
//!
//! A body that parses as JSON but does not fit its DTO (a property missing, `null` or of the wrong
//! type, or one the DTO does not have) names every failing property by its wire name and never by
//! a container (`body`, `query`): a client keys its form errors by property. The answer's
//! `status`, `code`, top-level message and the set of distinct `field` values are what both
//! libraries share. The messages are this crate's own and name only the property, never the value
//! or the type the client sent.
//!
//! The properties come from the shared request schemas (`properties`, `required`), not from serde's
//! text. When a request fails structurally, the failing properties are replaced by a harmless
//! stand-in and the rest of the request still goes through the DTO's own validation, so a request
//! that fails one property by shape and another by bound reports both.

use std::any::type_name;
use std::collections::BTreeMap;

use bymax_auth_types::FieldError;
use garde::Validate;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::request_schemas::schema;
use crate::validation::garde_details;

/// How a property fails the shape of its DTO.
pub(crate) enum Failure {
    /// A required property is absent or `null`.
    Missing,
    /// A property is present and not a string. `required` says whether it can be left out.
    WrongType { required: bool },
    /// A property the DTO does not have, on a DTO that refuses them.
    Unknown,
}

impl Failure {
    /// The message for `name`: fixed, naming only the property.
    fn message(&self, name: &str) -> String {
        match self {
            Self::Missing => format!("{name} is required."),
            Self::WrongType { .. } => format!("{name} must be a string."),
            Self::Unknown if name == CONTAINER => {
                "the request has a property that should not exist.".to_owned()
            }
            Self::Unknown => format!("property {name} should not exist."),
        }
    }
}

/// The schema a DTO type is described by, and whether it refuses properties it does not have, for
/// a type name. A type that is not one of this crate's DTOs has no schema, and a failure of it
/// keeps naming its container. The full type name is the key: a host type that shares a short
/// name is not one of these.
pub(crate) fn declared_named(name: &str) -> Option<(&'static str, bool)> {
    crate::dto::DECLARED
        .iter()
        .find(|(ty, ..)| *ty == name)
        .map(|(_, schema, denies)| (*schema, *denies))
}

/// The properties of `body` that fail the shape of `schema_name`, by wire name.
pub(crate) fn failures(
    schema_name: &str,
    denies_unknown: bool,
    body: &Map<String, Value>,
) -> BTreeMap<String, Failure> {
    let mut found = BTreeMap::new();
    if let Some(schema) = schema(schema_name) {
        scan(schema, denies_unknown, body, &mut found);
    }
    found
}

/// Records in `found` each property of `body` that fails `schema`.
fn scan(
    schema: &Value,
    denies_unknown: bool,
    body: &Map<String, Value>,
    found: &mut BTreeMap<String, Failure>,
) {
    let properties = schema["properties"].as_object();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    for name in properties.into_iter().flatten().map(|(name, _)| name) {
        let is_required = required.contains(&name.as_str());
        match body.get(name) {
            None | Some(Value::Null) if is_required => {
                found.insert(name.clone(), Failure::Missing);
            }
            Some(value) if !value.is_null() && !value.is_string() => {
                found.insert(
                    name.clone(),
                    Failure::WrongType {
                        required: is_required,
                    },
                );
            }
            _ => {}
        }
    }
    if denies_unknown {
        let known = |name: &str| properties.is_some_and(|map| map.contains_key(name));
        for name in body.keys().filter(|name| !known(name)) {
            found.insert(name.clone(), Failure::Unknown);
        }
    }
}

/// The field an unknown property is reported under when its name is not echoed.
const CONTAINER: &str = "body";

/// The longest unknown property name echoed back, in characters.
const MAX_ECHOED_NAME: usize = 128;

/// The field a failing property is reported under. A property the DTO has is reported by its
/// name. An unknown one is echoed only when it is a plausible name; one that is long or carries a
/// control character is reported under the container, so a client cannot make the answer as large
/// as its request or fill it with control bytes.
fn reported(name: &str, failure: &Failure) -> String {
    let echoed = match failure {
        Failure::Unknown => {
            name.chars().count() <= MAX_ECHOED_NAME && !name.chars().any(char::is_control)
        }
        _ => true,
    };
    if echoed {
        name.to_owned()
    } else {
        CONTAINER.to_owned()
    }
}

/// `body` with every failing property replaced by a stand-in the DTO can read: an empty string
/// for a required property, and nothing for an optional or unknown one.
fn repaired(body: &Map<String, Value>, failing: &BTreeMap<String, Failure>) -> Value {
    let mut fixed = body.clone();
    for (name, failure) in failing {
        match failure {
            Failure::Missing | Failure::WrongType { required: true } => {
                fixed.insert(name.clone(), Value::String(String::new()));
            }
            Failure::WrongType { required: false } | Failure::Unknown => {
                fixed.remove(name);
            }
        }
    }
    Value::Object(fixed)
}

/// The first segment of a wire path (`name` of `name.inner`).
fn root(field: &str) -> &str {
    field.split('.').next().unwrap_or(field)
}

/// The details for a request that does not fit `T`: one entry per failing property, then the
/// DTO's own validation of the rest. Empty when nothing structural can be named, which leaves the
/// caller to answer with the container.
pub(crate) fn details_for<T>(body: &Map<String, Value>) -> Vec<FieldError>
where
    T: DeserializeOwned + Validate<Context = ()>,
{
    let rest = |value: Value| {
        let checked = serde_json::from_value::<T>(value).map(|dto| dto.validate());
        match checked {
            Ok(Err(report)) => garde_details(&report),
            _ => Vec::new(),
        }
    };
    explain(declared_named(type_name::<T>()), body, &rest)
}

/// One entry per failing property of `body`, then what `rest` finds in the repaired body.
fn explain(
    declared: Option<(&str, bool)>,
    body: &Map<String, Value>,
    rest: &dyn Fn(Value) -> Vec<FieldError>,
) -> Vec<FieldError> {
    let Some((schema_name, denies_unknown)) = declared else {
        return Vec::new();
    };
    let failing = failures(schema_name, denies_unknown, body);
    let mut details: Vec<FieldError> = Vec::new();
    for (name, failure) in &failing {
        let field = reported(name, failure);
        // Several names that are not echoed share the container's one entry.
        if details.iter().all(|detail| detail.field != field) {
            details.push(FieldError {
                message: failure.message(&field),
                field,
            });
        }
    }
    details.extend(
        rest(repaired(body, &failing))
            .into_iter()
            .filter(|detail| !failing.contains_key(root(&detail.field))),
    );
    details
}
