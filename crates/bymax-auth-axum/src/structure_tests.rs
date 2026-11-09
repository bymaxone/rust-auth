//! Every request DTO against the shared request schemas: a request that does not fit names each
//! failing property by its wire name, and the table of DTOs is the artefact's, in both directions.

use std::any::type_name;
use std::collections::BTreeSet;

use bymax_auth_types::FieldError;
use serde_json::{Map, Value, json};

use crate::dto::{
    AcceptInvitationDto, ChangeEmailDto, ChangePasswordDto, ConfirmEmailChangeDto,
    CreateInvitationDto, DECLARED, ForgotPasswordDto, LoginDto, MfaChallengeDto, MfaDisableDto,
    MfaRegenerateRecoveryCodesDto, MfaSetupDto, MfaVerifyDto, OAuthCallbackQuery,
    OAuthInitiateQuery, PlatformLoginDto, RegisterDto, ResendOtpDto, ResendVerificationDto,
    ResetPasswordDto, RevokeInvitationDto, VerifyEmailDto, VerifyOtpDto,
};
use crate::request_schemas::schema;
use crate::structure::{declared_named, details_for};

/// What a DTO answers for a body that does not fit it.
type Details = fn(&Map<String, Value>) -> Vec<FieldError>;

/// Whether serde itself refuses a property the DTO does not have, on a body that is otherwise
/// the required properties as strings.
type Refuses = fn(&str) -> bool;

fn refuses<T: serde::de::DeserializeOwned>(name: &str) -> bool {
    let base: Map<String, Value> = required(name)
        .into_iter()
        .map(|property| (property, json!("x")))
        .collect();
    let mut extra = base.clone();
    extra.insert("zzUnknown".to_owned(), json!("x"));
    assert!(
        serde_json::from_value::<T>(Value::Object(base)).is_ok(),
        "{name}"
    );
    serde_json::from_value::<T>(Value::Object(extra)).is_err()
}

macro_rules! dto {
    ($ty:ty, $schema:literal) => {
        (
            $schema,
            |body: &Map<String, Value>| details_for::<$ty>(body),
            |name: &str| refuses::<$ty>(name),
        )
    };
}

/// Every DTO, by the name of its schema.
const DTOS: [(&str, Details, Refuses); 22] = [
    dto!(AcceptInvitationDto, "AcceptInvitationDto"),
    dto!(ChangeEmailDto, "ChangeEmailDto"),
    dto!(ChangePasswordDto, "ChangePasswordDto"),
    dto!(ConfirmEmailChangeDto, "ConfirmEmailChangeDto"),
    dto!(CreateInvitationDto, "CreateInvitationDto"),
    dto!(ForgotPasswordDto, "ForgotPasswordDto"),
    dto!(LoginDto, "LoginDto"),
    dto!(MfaChallengeDto, "MfaChallengeDto"),
    dto!(MfaDisableDto, "MfaDisableDto"),
    dto!(
        MfaRegenerateRecoveryCodesDto,
        "MfaRegenerateRecoveryCodesDto"
    ),
    dto!(MfaSetupDto, "MfaSetupDto"),
    dto!(MfaVerifyDto, "MfaVerifyDto"),
    dto!(OAuthCallbackQuery, "OAuthCallbackQueryDto"),
    dto!(OAuthInitiateQuery, "OAuthInitiateQueryDto"),
    dto!(PlatformLoginDto, "PlatformLoginDto"),
    dto!(RegisterDto, "RegisterDto"),
    dto!(ResendOtpDto, "ResendOtpDto"),
    dto!(ResendVerificationDto, "ResendVerificationDto"),
    dto!(ResetPasswordDto, "ResetPasswordDto"),
    dto!(RevokeInvitationDto, "RevokeInvitationDto"),
    dto!(VerifyEmailDto, "VerifyEmailDto"),
    dto!(VerifyOtpDto, "VerifyOtpDto"),
];

fn properties(name: &str) -> BTreeSet<String> {
    schema(name)
        .and_then(|schema| schema["properties"].as_object())
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

fn required(name: &str) -> BTreeSet<String> {
    schema(name)
        .map(|schema| schema["required"].as_array().cloned().unwrap_or_default())
        .into_iter()
        .flatten()
        .filter_map(|name| name.as_str().map(str::to_owned))
        .collect()
}

fn fields(details: Vec<FieldError>) -> BTreeSet<String> {
    details.into_iter().map(|detail| detail.field).collect()
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// The properties of the DTO the artefact names that a body made of `value` for each of them
/// fails.
fn failing_with(name: &str, details: Details, value: &Value) -> BTreeSet<String> {
    let body: Map<String, Value> = properties(name)
        .into_iter()
        .map(|property| (property, value.clone()))
        .collect();
    fields(details(&body))
}

#[test]
fn the_declared_table_is_the_artefacts_schemas_and_each_dto_is_found_by_its_type() {
    let names: BTreeSet<&str> = DECLARED.iter().map(|(_, schema, _)| *schema).collect();
    let tabled: BTreeSet<&str> = DTOS.iter().map(|(name, ..)| *name).collect();
    assert_eq!(names.len(), DECLARED.len(), "a schema is declared twice");
    assert_eq!(names, tabled);
    for (name, ..) in DTOS {
        assert!(schema(name).is_some(), "{name} is not in the artefact");
    }
    assert_eq!(
        declared_named(type_name::<LoginDto>()),
        Some(("LoginDto", true))
    );
    assert_eq!(
        declared_named(type_name::<OAuthCallbackQuery>()),
        Some(("OAuthCallbackQueryDto", false))
    );
    // A type of a host that shares a short name is not one of these.
    mod host {
        pub struct LoginDto;
    }
    assert_eq!(declared_named(type_name::<host::LoginDto>()), None);
}

#[test]
fn an_empty_body_names_exactly_the_required_properties() {
    for (name, details, _) in DTOS {
        assert_eq!(fields(details(&Map::new())), required(name), "{name}");
    }
}

#[test]
fn a_null_required_property_is_named_as_a_missing_one() {
    for (name, details, _) in DTOS {
        let body: Map<String, Value> = required(name)
            .into_iter()
            .map(|property| (property, Value::Null))
            .collect();
        assert_eq!(fields(details(&body)), required(name), "{name}");
    }
}

#[test]
fn a_value_of_the_wrong_type_names_its_property() {
    for (name, details, _) in DTOS {
        // The queries read strings only, so a type cannot be wrong there.
        let queries = ["OAuthCallbackQueryDto", "OAuthInitiateQueryDto"];
        if !queries.contains(&name) {
            assert_eq!(
                failing_with(name, details, &json!(5)),
                properties(name),
                "{name}"
            );
        }
    }
}

/// Whether the declared table says the DTO of schema `name` refuses unknown properties.
fn declared_to_refuse(name: &str) -> bool {
    DECLARED
        .iter()
        .find(|(_, schema, _)| *schema == name)
        .is_some_and(|(_, _, denies)| *denies)
}

#[test]
fn an_unknown_property_is_named_where_the_dto_refuses_it_and_only_there() {
    for (name, details, _) in DTOS {
        let mut body: Map<String, Value> = required(name)
            .into_iter()
            .map(|property| (property, json!("x")))
            .collect();
        body.insert("zzUnknown".to_owned(), json!("x"));
        let named = fields(details(&body));
        assert_eq!(
            named.contains("zzUnknown"),
            declared_to_refuse(name),
            "{name}"
        );
    }
}

#[test]
fn what_serde_does_with_an_unknown_property_is_what_the_declared_table_says() {
    // The flag is what names a property the DTO refuses; this reads the refusal off serde itself,
    // so a DTO that gains or loses `deny_unknown_fields` fails here and not in front of a client.
    let mut refusing = 0;
    for (name, _, refused) in DTOS {
        assert_eq!(refused(name), declared_to_refuse(name), "{name}");
        refusing += usize::from(refused(name));
    }
    assert_eq!(
        refusing,
        DTOS.len() - 1,
        "only the OAuth callback ignores unknown properties"
    );
}

#[test]
fn a_name_that_is_not_plausible_is_not_echoed() {
    let long = "a".repeat(200);
    for name in [long.as_str(), "line\nbreak", "bell\u{7}"] {
        let mut body = Map::new();
        body.insert(name.to_owned(), json!(1));
        body.insert("email".to_owned(), json!("a@e.com"));
        body.insert("password".to_owned(), json!("p"));
        let named = fields(details_for::<LoginDto>(&body));
        assert_eq!(named, BTreeSet::from(["body".to_owned()]), "{name:?}");
    }
}

#[test]
fn a_request_that_fails_by_shape_and_by_bound_names_both_without_naming_a_good_property() {
    let body = object(&json!({ "email": "not-an-email", "password": 5 }));
    assert_eq!(
        fields(details_for::<LoginDto>(&body)),
        BTreeSet::from(["email".to_owned(), "password".to_owned()])
    );
    let fine = object(&json!({ "email": "a@e.com", "password": 5 }));
    assert_eq!(
        fields(details_for::<LoginDto>(&fine)),
        BTreeSet::from(["password".to_owned()])
    );
}

#[test]
fn lengths_count_code_points_at_an_astral_boundary() {
    // `name` of RegisterDto is 2 to 128 characters. One astral character is one code point (two
    // UTF-16 units, four bytes), so 128 of them fit, 129 do not, and a single one is too short.
    let astral = |count: usize| "\u{1F600}".repeat(count);
    let named = |name: String| {
        let body = object(&json!({
            "email": "a@e.com", "password": "glidingwalnut42", "name": name, "x": 1
        }));
        fields(details_for::<RegisterDto>(&body))
    };
    let only_unknown = BTreeSet::from(["x".to_owned()]);
    for (count, bound_fails) in [(1, true), (2, false), (128, false), (129, true)] {
        let mut expected = only_unknown.clone();
        if bound_fails {
            expected.insert("name".to_owned());
        }
        assert_eq!(named(astral(count)), expected, "{count} astral characters");
    }
}

fn messages(details: &[FieldError]) -> Vec<(String, String)> {
    details
        .iter()
        .map(|detail| (detail.field.clone(), detail.message.clone()))
        .collect()
}

#[test]
fn a_message_names_the_property_and_nothing_the_client_sent() {
    let missing = details_for::<LoginDto>(&Map::new());
    assert_eq!(
        messages(&missing),
        [
            ("email".to_owned(), "email is required.".to_owned()),
            ("password".to_owned(), "password is required.".to_owned()),
        ]
    );
    let wrong = object(&json!({ "email": "a@e.com", "password": 5 }));
    assert_eq!(
        messages(&details_for::<LoginDto>(&wrong)),
        [(
            "password".to_owned(),
            "password must be a string.".to_owned()
        )]
    );
    let unknown = object(&json!({ "email": "a@e.com", "password": "p", "zz": 1 }));
    assert_eq!(
        messages(&details_for::<LoginDto>(&unknown)),
        [("zz".to_owned(), "property zz should not exist.".to_owned())]
    );
    let long = object(&json!({ "email": "a@e.com", "password": "p", "q".repeat(200): 1 }));
    assert_eq!(
        messages(&details_for::<LoginDto>(&long)),
        [(
            "body".to_owned(),
            "the request has a property that should not exist.".to_owned()
        )]
    );
}

#[test]
fn a_failing_property_is_not_reported_again_for_its_stand_in() {
    // `password` is a number, so it is replaced by an empty string, which the password rule
    // would refuse too. Only the shape failure is reported for it, and the other property's own
    // failure still is.
    let body = object(&json!({ "email": "not-an-email", "password": 5, "name": "Nm" }));
    let details = details_for::<RegisterDto>(&body);
    let for_password = details.iter().filter(|d| d.field == "password").count();
    assert_eq!(for_password, 1, "{details:?}");
    assert!(details.iter().any(|d| d.field == "email"), "{details:?}");
}

#[test]
fn nothing_is_named_for_a_schema_or_a_type_the_adapter_does_not_know() {
    assert!(crate::structure::failures("NoSuchSchema", true, &Map::new()).is_empty());
    #[derive(serde::Deserialize, garde::Validate)]
    struct HostDto {
        #[garde(skip)]
        _name: String,
    }
    assert!(details_for::<HostDto>(&Map::new()).is_empty());
}
